// SPDX-License-Identifier: Apache-2.0
use crate::apdu::Header;

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

/// Owns a source lease, not its storage. Drop, cancellation, completion and read
/// errors close the lease exactly once. A session must own this object and drop
/// it on reset/preemption; there is no global state or implicit hardware lock.
pub struct Response<'a> {
    source: Option<&'a mut dyn Source>,
    total: u32,
    offset: u32,
    final_sw: StatusWord,
}

impl<'a> Response<'a> {
    pub fn new(source: &'a mut dyn Source, total: u32, final_sw: StatusWord) -> Self {
        Self {
            source: Some(source),
            total,
            offset: 0,
            final_sw,
        }
    }

    pub fn active(&self) -> bool {
        self.source.is_some()
    }
    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn clear(&mut self) {
        if let Some(source) = self.source.take() {
            source.close();
        }
    }

    /// Call before dispatch. A new command abandons this response even if it
    /// subsequently fails. GET RESPONSE without an active lease is an error.
    pub fn command(&mut self, header: Header) -> Result<(), StatusWord> {
        if !header.is_get_response() {
            self.clear();
            return Ok(());
        }
        if self.active() {
            Ok(())
        } else {
            Err(StatusWord::COMMAND_NOT_ALLOWED)
        }
    }

    /// output is payload-only; the caller owns trailer space and chunk policy.
    /// Zero Le/capacity makes no progress and preserves the pending response.
    pub fn next(&mut self, output: &mut [u8], le: u32) -> Result<Chunk, StatusWord> {
        let Some(source) = self.source.as_mut() else {
            return Err(StatusWord::COMMAND_NOT_ALLOWED);
        };
        let remaining = self.total - self.offset;
        let n = output.len().min(remaining.min(le) as usize);
        if remaining == 0 {
            let sw = self.final_sw;
            self.clear();
            return Ok(Chunk { len: 0, sw });
        }
        if n == 0 {
            return Ok(Chunk {
                len: 0,
                sw: StatusWord::remaining(remaining),
            });
        }
        let read = source.read(self.offset, &mut output[..n]);
        let len = match read {
            Ok(len) if len > 0 && len <= n => len,
            _ => {
                // Do not expose a partially written response on callback failure.
                output[..n].fill(0);
                self.clear();
                return Err(StatusWord::UNABLE_TO_PROCESS);
            }
        };
        let plan = ResponsePlan::new(self.total, self.offset, len as u32, self.final_sw)?;
        self.offset = plan.next;
        if plan.complete {
            self.clear();
        }
        Ok(Chunk { len, sw: plan.sw })
    }
}

impl Drop for Response<'_> {
    fn drop(&mut self) {
        self.clear();
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
