// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}

impl Header {
    pub fn is_get_response(self) -> bool {
        matches!(self.cla, 0x00 | 0x80) && self.ins == 0xc0
    }

    pub fn chained(self) -> bool {
        self.cla & 0x10 != 0
    }

    pub fn unchained(self) -> Self {
        Self {
            cla: self.cla & !0x10,
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Consumer,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandInfo {
    pub header: Header,
    pub lc: u16,
    /// None means Le is absent on the wire. Zero encodings are expanded.
    pub le: Option<u32>,
    pub extended: bool,
}

impl CommandInfo {
    /// Compatibility with build_capdu(): Case 3 receives an implicit maximum Le.
    pub fn legacy_le(self) -> u32 {
        self.le.unwrap_or(if self.lc == 0 {
            0
        } else if self.extended {
            65536
        } else {
            256
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command<'a> {
    pub info: CommandInfo,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    start: usize,
    lc: u16,
    le_width: usize,
    extended: bool,
}

impl Layout {
    fn decode(prefix: &[u8], total: usize) -> Result<Self, Error> {
        let mut result = Self {
            start: 4,
            lc: 0,
            le_width: 0,
            extended: false,
        };
        if total == 4 {
            return Ok(result);
        }
        if total == 5 {
            result.le_width = 1;
            return Ok(result);
        }
        let short_lc = usize::from(prefix[4]);
        if short_lc != 0 {
            result.start = 5;
            result.lc = short_lc as u16;
            result.le_width = total.checked_sub(5 + short_lc).ok_or(Error::Length)?;
            if result.le_width > 1 {
                return Err(Error::Length);
            }
        } else {
            if total < 7 {
                return Err(Error::Length);
            }
            result.extended = true;
            if total == 7 {
                result.start = 5;
                result.le_width = 2;
            } else {
                result.start = 7;
                result.lc = u16::from_be_bytes([prefix[5], prefix[6]]);
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

/// Parse format only. Transport capacity and extended-APDU admission are caller policy.
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
/// its semantic state on any error/cancellation and must not persist side effects.
/// Transport packets and ISO command-chain fragments are distinct boundaries.
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

    pub fn feed(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
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
                    if emit(&bytes[..n]).is_err() {
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

    pub fn finish(self) -> Result<CommandInfo, Error> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStep {
    /// Discard the previous command's provisional semantic state before use.
    pub restarted: bool,
    pub last: bool,
    pub total: u32,
}

/// Metadata only: the caller owns one incremental consumer, never a chain-sized
/// buffer. Apply after frame validation; overflow/reset aborts that consumer.
#[derive(Default)]
pub struct CommandChain {
    header: Option<Header>,
    total: u32,
}

impl CommandChain {
    pub const fn new() -> Self {
        Self {
            header: None,
            total: 0,
        }
    }
    pub fn active(&self) -> bool {
        self.header.is_some()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn accept(&mut self, info: CommandInfo, limit: u32) -> Result<ChainStep, Error> {
        let header = info.header.unchained();
        let restarted = self.header != Some(header);
        let total = if restarted { 0 } else { self.total };
        let Some(total) = total
            .checked_add(u32::from(info.lc))
            .filter(|n| *n <= limit)
        else {
            self.reset();
            return Err(Error::Length);
        };
        let last = !info.header.chained();
        if last {
            self.reset();
        } else {
            self.header = Some(header);
            self.total = total;
        }
        Ok(ChainStep {
            restarted,
            last,
            total,
        })
    }
}
