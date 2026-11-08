// SPDX-License-Identifier: Apache-2.0
//! Bounded NFC envelope storage. Large FIDO bodies use a transient staging lease.
use canokey_protocol::{apdu, response::StatusWord as Sw};

// C 3.1.2 NFC reserves the largest extended header/trailer even for Case3E.
pub const INLINE_BYTES: usize = 288;
pub const INLINE_DATA: usize = INLINE_BYTES - apdu::EXTENDED_OVERHEAD_BYTES;
const TAIL_BYTES: usize = INLINE_BYTES - apdu::SHORT_FRAME_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Status(Sw),
    TooLarge,
}
pub trait Backend {
    /// Apply prefix cleanup before acquiring the body lease. Only FIDO MSG
    /// replaces old input; response polls retain old output. Check selection,
    /// P1/P2 and request size in that order; never select implicitly.
    fn prepare(&mut self, prefix: &[u8; apdu::EXTENDED_HEADER_BYTES]) -> Result<(), Rejection>;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool;
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool;
    fn close(&mut self);
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Inline,
    Staged,
    Discard(Rejection),
    Malformed,
}
pub struct Request {
    tail: [u8; TAIL_BYTES],
    received: usize,
    body: usize,
    mode: Mode,
}
impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}
impl Request {
    pub const fn new() -> Self {
        Self {
            tail: [0; TAIL_BYTES],
            received: 0,
            body: 0,
            mode: Mode::Inline,
        }
    }
    pub fn len(&self) -> usize {
        self.received
    }
    pub fn is_empty(&self) -> bool {
        self.received == 0
    }
    /// After finish, distinguish invalid framing from a drained prefix rejection.
    pub fn is_malformed(&self) -> bool {
        self.mode == Mode::Malformed
    }
    pub fn reset(&mut self, backend: &mut impl Backend) {
        if self.mode == Mode::Staged {
            backend.close();
        }
        self.tail.fill(0);
        self.received = 0;
        self.body = 0;
        self.mode = Mode::Inline;
    }
    /// Called only for accepted (non-repeated) blocks. Rejections keep draining
    /// legal RF blocks so an APDU error does not tear down the activation.
    pub fn append(&mut self, mut bytes: &[u8], inline: &mut [u8], backend: &mut impl Backend) {
        assert!(inline.len() >= apdu::SHORT_FRAME_BYTES);
        while !bytes.is_empty() {
            let pos = self.received;
            // Exactly seven bytes are Case2E. Only the arrival of a body byte
            // permits interpreting bytes5/6 as Lc and borrowing PKE.
            if self.mode == Mode::Inline && pos == apdu::EXTENDED_HEADER_BYTES && inline[4] == 0 {
                self.body = usize::from(u16::from_be_bytes([inline[5], inline[6]]));
                if self.body > INLINE_DATA {
                    self.mode = match backend.prepare(inline[..7].try_into().unwrap()) {
                        Ok(()) => Mode::Staged,
                        Err(rejection) => Mode::Discard(rejection),
                    };
                }
            }
            let count = match self.mode {
                Mode::Malformed => bytes.len(),
                Mode::Inline => {
                    if pos >= INLINE_BYTES {
                        self.mode = Mode::Malformed;
                        continue;
                    }
                    if pos < apdu::SHORT_FRAME_BYTES {
                        let end = if pos < 7 { 7 } else { apdu::SHORT_FRAME_BYTES };
                        let n = bytes.len().min(end - pos);
                        inline[pos..pos + n].copy_from_slice(&bytes[..n]);
                        n
                    } else {
                        let n = bytes.len().min(INLINE_BYTES - pos);
                        let start = pos - apdu::SHORT_FRAME_BYTES;
                        self.tail[start..start + n].copy_from_slice(&bytes[..n]);
                        n
                    }
                }
                Mode::Staged | Mode::Discard(_) => {
                    let end = apdu::EXTENDED_HEADER_BYTES + self.body;
                    if pos < end {
                        let n = bytes.len().min(end - pos);
                        if self.mode == Mode::Staged && !backend.write(pos - 7, &bytes[..n]) {
                            backend.close();
                            self.mode = Mode::Discard(Rejection::Status(Sw::UNABLE_TO_PROCESS));
                        }
                        n
                    } else if pos < end + apdu::EXTENDED_LE_BYTES {
                        let n = bytes.len().min(end + apdu::EXTENDED_LE_BYTES - pos);
                        self.tail[pos - end..pos - end + n].copy_from_slice(&bytes[..n]);
                        n
                    } else {
                        if self.mode == Mode::Staged {
                            backend.close();
                        }
                        self.mode = Mode::Malformed;
                        continue;
                    }
                }
            };
            self.received = match pos.checked_add(count) {
                Some(n) => n,
                None => {
                    if self.mode == Mode::Staged {
                        backend.close();
                    }
                    self.mode = Mode::Malformed;
                    usize::MAX
                }
            };
            bytes = &bytes[count..];
        }
    }
    /// Inline structural validation stays in the shared FrameDecoder. A staged
    /// or discarded envelope must be exact before its recorded status is used.
    pub fn finish(&mut self, backend: &mut impl Backend) -> Result<(), Rejection> {
        let end = apdu::EXTENDED_HEADER_BYTES + self.body;
        if self.mode == Mode::Malformed
            || (self.mode != Mode::Inline && self.received != end && self.received != end + 2)
        {
            if self.mode == Mode::Staged {
                backend.close();
            }
            self.mode = Mode::Malformed;
            return Err(Rejection::Status(Sw::WRONG_LENGTH));
        }
        if let Mode::Discard(rejection) = self.mode {
            Err(rejection)
        } else {
            Ok(())
        }
    }
    pub fn read(
        &self,
        mut offset: usize,
        mut out: &mut [u8],
        inline: &[u8],
        backend: &mut impl Backend,
    ) -> bool {
        if offset > self.received || out.len() > self.received - offset {
            return false;
        }
        while !out.is_empty() {
            let count = match self.mode {
                Mode::Inline if offset < apdu::SHORT_FRAME_BYTES => {
                    let n = out.len().min(apdu::SHORT_FRAME_BYTES - offset);
                    out[..n].copy_from_slice(&inline[offset..offset + n]);
                    n
                }
                Mode::Inline => {
                    let start = offset - apdu::SHORT_FRAME_BYTES;
                    let n = out.len();
                    out.copy_from_slice(&self.tail[start..start + n]);
                    n
                }
                Mode::Staged if offset < 7 => {
                    let n = out.len().min(7 - offset);
                    out[..n].copy_from_slice(&inline[offset..offset + n]);
                    n
                }
                Mode::Staged if offset < 7 + self.body => {
                    let n = out.len().min(7 + self.body - offset);
                    if !backend.read(offset - 7, &mut out[..n]) {
                        return false;
                    }
                    n
                }
                Mode::Staged => {
                    let start = offset - 7 - self.body;
                    let n = out.len();
                    out.copy_from_slice(&self.tail[start..start + n]);
                    n
                }
                _ => return false,
            };
            offset += count;
            out = &mut out[count..];
        }
        true
    }
}
