// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusWord(pub u16);

impl StatusWord {
    pub const SUCCESS: Self = Self(0x9000);
    pub const FILE_NOT_FOUND: Self = Self(0x6a82);
    pub const INS_NOT_SUPPORTED: Self = Self(0x6d00);
    pub const CLA_NOT_SUPPORTED: Self = Self(0x6e00);
    pub const SECURITY_STATUS_NOT_SATISFIED: Self = Self(0x6982);
    pub const AUTHENTICATION_BLOCKED: Self = Self(0x6983);
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);
    pub const PERSISTENCE_ERROR: Self = Self(0x6500);
    pub const WRONG_LENGTH: Self = Self(0x6700);
    pub const WRONG_DATA: Self = Self(0x6a80);
    pub const WRONG_P1P2: Self = Self(0x6a86);
    pub const UNABLE_TO_PROCESS: Self = Self(0x6900);
    pub const COMMAND_NOT_ALLOWED: Self = Self(0x6986);

    pub fn remaining(bytes: u32) -> Self {
        Self(0x6100 | bytes.min(255) as u16)
    }
    pub fn bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadError;

/// The source must remain valid until close, including across GET RESPONSE.
/// This excludes transient request PKE storage that crypto may overwrite.
/// read may return a positive short read, but never more than output.len().
/// Source and output must not alias; an in-place C bridge needs its own adapter.
pub trait Source {
    fn read(&mut self, offset: u32, output: &mut [u8]) -> Result<usize, ReadError>;
    fn close(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub len: usize,
    pub sw: StatusWord,
}

/// Owns continuation metadata. The runtime owns the source handle and supplies
/// a fresh borrow per call, avoiding self-referential applet/source references.
#[derive(Default)]
pub struct Response {
    pending: Option<Pending>,
}
#[derive(Clone, Copy)]
struct Pending {
    total: u32,
    offset: u32,
    sw: StatusWord,
}
impl Response {
    pub const fn new() -> Self {
        Self { pending: None }
    }
    pub fn active(&self) -> bool {
        self.pending.is_some()
    }
    pub fn start(&mut self, total: u32, sw: StatusWord) {
        debug_assert!(!self.active());
        self.pending = Some(Pending {
            total,
            offset: 0,
            sw,
        });
    }
    pub fn clear(&mut self, source: &mut dyn Source) {
        if self.pending.take().is_some() {
            source.close();
        }
    }
    /// Source reads are monotonic. Transport retries resend their owned chunk,
    /// rather than rewinding a generator or repeating a credential operation.
    pub fn next(
        &mut self,
        source: &mut dyn Source,
        output: &mut [u8],
        le: u32,
    ) -> Result<Chunk, StatusWord> {
        let p = self.pending.ok_or(StatusWord::COMMAND_NOT_ALLOWED)?;
        let plan = ResponsePlan::new(p.total, p.offset, le.min(output.len() as u32), p.sw)?;
        let n = plan.length as usize;
        let len = if n == 0 {
            0
        } else {
            match source.read(p.offset, &mut output[..n]) {
                Ok(nread) if nread > 0 && nread <= n => nread,
                _ => {
                    output[..n].fill(0);
                    self.clear(source);
                    return Err(StatusWord::UNABLE_TO_PROCESS);
                }
            }
        };
        let plan = ResponsePlan::new(p.total, p.offset, len as u32, p.sw)?;
        if plan.complete {
            self.clear(source);
        } else {
            self.pending = Some(Pending {
                offset: plan.next,
                ..p
            });
        }
        Ok(Chunk { len, sw: plan.sw })
    }
}

/// Pure continuation arithmetic shared by safe Rust streams and the C adapter.
/// Storage aliases and source callbacks remain outside this value calculation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponsePlan {
    pub next: u32,
    pub length: u32,
    pub sw: StatusWord,
    pub complete: bool,
}

impl ResponsePlan {
    pub fn new(
        total: u32,
        offset: u32,
        limit: u32,
        final_sw: StatusWord,
    ) -> Result<Self, StatusWord> {
        let remaining = total
            .checked_sub(offset)
            .ok_or(StatusWord::UNABLE_TO_PROCESS)?;
        let length = remaining.min(limit);
        let next = offset + length;
        let complete = next == total;
        Ok(Self {
            next,
            length,
            complete,
            sw: if complete {
                final_sw
            } else {
                StatusWord::remaining(total - next)
            },
        })
    }
}
