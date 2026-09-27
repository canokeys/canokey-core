// SPDX-License-Identifier: Apache-2.0
use super::{Command, CommandInfo, Error, Header};
#[derive(Clone, Copy, Debug)]
struct Layout {
    start: usize,
    lc: u16,
    le_width: usize,
    extended: bool,
}

impl Layout {
    fn decode(frame: &[u8], total: usize) -> Result<Self, Error> {
        let mut result = Self {
            start: 4,
            lc: 0,
            le_width: 0,
            extended: false,
        };
        // ISO case 1: just CLA/INS/P1/P2, with neither body nor expected length.
        if total == 4 {
            return Ok(result);
        }
        // ISO case 2S: the fifth byte is Le, not Lc, because no body follows.
        if total == 5 {
            result.le_width = 1;
            return Ok(result);
        }
        let short_lc = usize::from(frame[4]);
        // Cases 3S/4S: nonzero fifth byte is short Lc. Exactly zero or one
        // trailing byte is permitted (absent Le or short Le).
        if short_lc != 0 {
            result.start = 5;
            result.lc = short_lc as u16;
            result.le_width = total.checked_sub(5 + short_lc).ok_or(Error::Length)?;
            if result.le_width > 1 {
                return Err(Error::Length);
            }
        } else {
            // Fifth byte 00 introduces extended form, needing two more bytes.
            // Seven-byte frames are case 2E (Le only); longer frames carry Lc.
            if total < 7 {
                return Err(Error::Length);
            }
            result.extended = true;
            if total == 7 {
                result.start = 5;
                result.le_width = 2;
            } else {
                result.start = 7;
                result.lc = u16::from_be_bytes([frame[5], frame[6]]);
                result.le_width = total
                    .checked_sub(7 + usize::from(result.lc))
                    .ok_or(Error::Length)?;
                if result.lc == 0 || !matches!(result.le_width, 0 | 2) {
                    return Err(Error::Length);
                }
            }
        }
        Ok(result)
    }

    fn info(self, head: &[u8], tail: [u8; 2]) -> CommandInfo {
        // Encoded Le=0 requests the format maximum, not a zero-byte reply:
        // 256 for short APDUs, 65536 for extended APDUs. None means absent.
        let le = match self.le_width {
            1 => Some(if tail[0] == 0 {
                256
            } else {
                u32::from(tail[0])
            }),
            2 => Some(match u16::from_be_bytes(tail) {
                0 => 65536,
                v => u32::from(v),
            }),
            _ => None,
        };
        CommandInfo {
            header: Header {
                cla: head[0],
                ins: head[1],
                p1: head[2],
                p2: head[3],
            },
            lc: self.lc,
            le,
            extended: self.extended,
        }
    }
}

/// Parse format only. Transport capacity and extended-APDU admission are caller
/// policy. This compatibility API is retained for host callers and integration
/// tests; firmware transport uses `FrameDecoder::feed_events` to avoid reassembly.
#[doc(hidden)]
pub fn parse(bytes: &[u8]) -> Result<Command<'_>, Error> {
    if bytes.len() < 4 || bytes.len() > 65544 {
        return Err(Error::Length);
    }
    let layout = Layout::decode(bytes, bytes.len())?;
    let end = layout.start + usize::from(layout.lc);
    let mut tail = [0; 2];
    tail[..layout.le_width].copy_from_slice(&bytes[end..]);
    Ok(Command {
        info: layout.info(bytes, tail),
        data: &bytes[layout.start..end],
    })
}

/// Decode one APDU whose total frame length is supplied by the transport.
/// Payload slices are borrowed only during emit; no payload is retained or reread.
/// Emissions are provisional until finish succeeds. The consumer must discard
/// its semantic state on any error/cancellation. Authorized incremental effects
/// require an explicit command-specific abort/publication contract.
/// Transport packets and ISO command-chain fragments are distinct boundaries.
#[derive(Clone, Copy, Debug)]
pub enum FrameEvent<'a> {
    Start(CommandInfo),
    Data(&'a [u8]),
}
pub struct FrameDecoder {
    total: usize,
    received: usize,
    head: [u8; 7],
    tail: [u8; 2],
    layout: Option<Layout>,
    failed: bool,
}

impl FrameDecoder {
    pub fn new(total: usize) -> Result<Self, Error> {
        if !(4..=65544).contains(&total) {
            return Err(Error::Length);
        }
        Ok(Self {
            total,
            received: 0,
            head: [0; 7],
            tail: [0; 2],
            layout: None,
            failed: false,
        })
    }

    pub fn feed_events(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(FrameEvent<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if bytes.len() > self.total - self.received {
            self.failed = true;
            return Err(Error::Length);
        }
        while !bytes.is_empty() {
            if let Some(layout) = self.layout {
                let end = layout.start + usize::from(layout.lc);
                if self.received < end {
                    let n = bytes.len().min(end - self.received);
                    if emit(FrameEvent::Data(&bytes[..n])).is_err() {
                        self.failed = true;
                        return Err(Error::Consumer);
                    }
                    self.received += n;
                    bytes = &bytes[n..];
                } else {
                    let offset = self.received - end;
                    self.tail[offset..offset + bytes.len()].copy_from_slice(bytes);
                    self.received += bytes.len();
                    bytes = &[];
                }
            } else {
                self.head[self.received] = bytes[0];
                self.received += 1;
                bytes = &bytes[1..];
                let ready = self.received == self.total
                    || (self.received >= 5 && self.head[4] != 0)
                    || self.received == 7;
                if !ready {
                    continue;
                }
                match Layout::decode(&self.head, self.total) {
                    Ok(layout) => {
                        // Case 2 Le is itself part of the buffered envelope.
                        if layout.lc == 0 && layout.le_width != 0 {
                            self.tail[..layout.le_width].copy_from_slice(
                                &self.head[layout.start..layout.start + layout.le_width],
                            );
                        }
                        self.layout = Some(layout);
                        let mut info = layout.info(&self.head, self.tail);
                        // Body routing does not depend on Le, which may be in the tail.
                        info.le = None;
                        if emit(FrameEvent::Start(info)).is_err() {
                            self.failed = true;
                            return Err(Error::Consumer);
                        }
                    }
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Body-only convenience for protocol callers; production uses header events.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.feed_events(bytes, &mut |event| match event {
            FrameEvent::Start(_) => Ok(()),
            FrameEvent::Data(bytes) => emit(bytes),
        })
    }
    pub fn finish(&self) -> Result<CommandInfo, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.received != self.total {
            return Err(Error::Length);
        }
        self.layout
            .map(|v| v.info(&self.head, self.tail))
            .ok_or(Error::Length)
    }
}
