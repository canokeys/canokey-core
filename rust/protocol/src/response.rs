// SPDX-License-Identifier: Apache-2.0

use core::num::NonZeroU16;

/// A nonzero APDU status word. Zero is not a response status; reserving it lets
/// Rust represent optional statuses and unit results without a separate tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StatusWord(NonZeroU16);

impl StatusWord {
    /// Construct a wire status, rejecting the reserved zero value.
    pub const fn new(value: u16) -> Option<Self> {
        match NonZeroU16::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub const fn value(self) -> u16 {
        self.0.get()
    }

    pub const REFERENCE_NOT_FOUND: Self = Self::new(0x6a88).unwrap();
    pub const SELECTED_FILE_TERMINATED: Self = Self::new(0x6285).unwrap();
    pub const EXECUTION_ERROR: Self = Self::new(0x6400).unwrap();
    pub const DATA_INVALID: Self = Self::new(0x6984).unwrap();
    pub const NOT_ENOUGH_MEMORY: Self = Self::new(0x6a84).unwrap();
    pub const SUCCESS: Self = Self::new(0x9000).unwrap();
    pub const FILE_NOT_FOUND: Self = Self::new(0x6a82).unwrap();
    pub const INS_NOT_SUPPORTED: Self = Self::new(0x6d00).unwrap();
    pub const CLA_NOT_SUPPORTED: Self = Self::new(0x6e00).unwrap();
    pub const SECURITY_STATUS_NOT_SATISFIED: Self = Self::new(0x6982).unwrap();
    pub const AUTHENTICATION_BLOCKED: Self = Self::new(0x6983).unwrap();
    pub const CONDITIONS_NOT_SATISFIED: Self = Self::new(0x6985).unwrap();
    pub const WRONG_LENGTH: Self = Self::new(0x6700).unwrap();
    pub const WRONG_DATA: Self = Self::new(0x6a80).unwrap();
    pub const WRONG_P1P2: Self = Self::new(0x6a86).unwrap();
    pub const UNABLE_TO_PROCESS: Self = Self::new(0x6900).unwrap();
    pub const COMMAND_NOT_ALLOWED: Self = Self::new(0x6986).unwrap();

    /// ISO 7816 63Cx: x is the remaining retry count (caller guarantees 0..15).
    pub fn retries(remaining: u8) -> Self {
        Self::new(0x63c0 | u16::from(remaining)).unwrap()
    }
    /// 61xx asks for GET RESPONSE. This profile caps the advertised next chunk
    /// at 255 bytes even when more data remains; it is not a total-length field.
    pub fn remaining(bytes: u32) -> Self {
        Self::new(0x6100 | bytes.min(255) as u16).unwrap()
    }
    pub fn bytes(self) -> [u8; 2] {
        self.value().to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadError(pub StatusWord);

/// The source must remain valid until close, including across GET RESPONSE.
/// This excludes transient request PKE storage that crypto may overwrite.
/// read may return a positive short read, but never more than output.len().
/// Source and output must not alias; an in-place C bridge needs its own adapter.
pub trait Source {
    fn read(&mut self, offset: u32, output: &mut [u8]) -> Result<usize, ReadError>;
    fn close(&mut self);
}

/// A requested byte window over consecutive response segments. Call `take`
/// once per segment, in wire order. The caller validates the complete response
/// length and supplies each segment's storage or generator; no source is retained.
pub struct ReadWindow<'a> {
    skip: usize,
    output: &'a mut [u8],
}

impl<'a> ReadWindow<'a> {
    pub fn new(offset: usize, output: &'a mut [u8]) -> Self {
        Self {
            skip: offset,
            output,
        }
    }

    /// Return the offset within this segment and its portion of the output.
    /// Empty portions need no source read, including at segment boundaries.
    #[inline(never)]
    pub fn take(&mut self, length: usize) -> (usize, &mut [u8]) {
        let start = self.skip.min(length);
        self.skip -= start;
        let count = (length - start).min(self.output.len());
        let (part, rest) = core::mem::take(&mut self.output).split_at_mut(count);
        self.output = rest;
        (start, part)
    }
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
    pub fn total(&self) -> u32 {
        self.pending.map_or(0, |pending| pending.total)
    }
    pub fn active(&self) -> bool {
        self.pending.is_some()
    }
    /// Start a response after the owning router has closed any previous source.
    /// `Response` deliberately does not own the source, so callers must use
    /// `clear`/their router close hook before replacing an active lease.
    pub fn start(&mut self, total: u32, sw: StatusWord) -> bool {
        // The engine closes the previous source before every start. Returning
        // false here also protects release builds if another caller violates
        // that contract.
        if self.active() {
            return false;
        }
        self.pending = Some(Pending {
            total,
            offset: 0,
            sw,
        });
        true
    }
    // Preserve the concrete source through the lifecycle calls. Firmware has
    // one routed source; callers with a trait object remain supported.
    pub fn clear(&mut self, source: &mut (impl Source + ?Sized)) {
        if self.pending.take().is_some() {
            source.close();
        }
    }
    /// Source reads are monotonic. Transport retries resend their owned chunk,
    /// rather than rewinding a generator or repeating a credential operation.
    pub fn next(
        &mut self,
        source: &mut (impl Source + ?Sized),
        output: &mut [u8],
        le: u32,
    ) -> Result<Chunk, StatusWord> {
        let p = self.pending.ok_or(StatusWord::COMMAND_NOT_ALLOWED)?;
        let remaining = p
            .total
            .checked_sub(p.offset)
            .ok_or(StatusWord::UNABLE_TO_PROCESS)?;
        let n = remaining.min(le).min(output.len() as u32) as usize;
        let len = if n == 0 {
            0
        } else {
            match source.read(p.offset, &mut output[..n]) {
                Ok(nread) if nread > 0 && nread <= n => nread,
                Err(error) => {
                    output[..n].fill(0);
                    self.clear(source);
                    return Err(error.0);
                }
                Ok(_) => {
                    output[..n].fill(0);
                    self.clear(source);
                    return Err(StatusWord::UNABLE_TO_PROCESS);
                }
            }
        };
        // A generator may return fewer bytes than requested. Advance by the
        // actual read, keeping the final status until every byte is delivered.
        // The read bound above proves len <= remaining; no second plan or
        // addition is needed, including when total is u32::MAX.
        let remaining = remaining - len as u32;
        let sw = if remaining == 0 {
            p.sw
        } else {
            StatusWord::remaining(remaining)
        };
        if remaining == 0 {
            self.clear(source);
        } else {
            self.pending = Some(Pending {
                offset: p.total - remaining,
                ..p
            });
        }
        Ok(Chunk { len, sw })
    }
}

/// Pure continuation arithmetic for callers planning a chunk without a source.
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

#[cfg(test)]
mod tests {
    #[test]
    fn status_words_preserve_wire_values_and_reserve_zero() {
        use super::StatusWord;
        assert_eq!(StatusWord::new(0), None);
        for value in 1..=u16::MAX {
            let status = StatusWord::new(value).unwrap();
            assert_eq!(status.value(), value);
            assert_eq!(status.bytes(), value.to_be_bytes());
        }
        // This representation is the reason for the nonzero invariant. No
        // code depends on the bit layout of Result or reads it through FFI.
        assert_eq!(core::mem::size_of::<Result<(), StatusWord>>(), 2);
        assert_eq!(core::mem::size_of::<Option<StatusWord>>(), 2);
    }

    use super::*;

    #[test]
    fn segmented_windows_match_contiguous_reads() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        // Empty, adjacent and split segments, with every requested subrange.
        for split in 0..=bytes.len() {
            let segments = [&[][..], &bytes[..split], &[][..], &bytes[split..], &[][..]];
            for offset in 0..=bytes.len() {
                for count in 0..=bytes.len() - offset {
                    let mut output = [0xa5; 34];
                    let mut window = ReadWindow::new(offset, &mut output[1..1 + count]);
                    for segment in segments {
                        let (start, dest) = window.take(segment.len());
                        dest.copy_from_slice(&segment[start..start + dest.len()]);
                    }
                    assert_eq!(&output[1..1 + count], &bytes[offset..offset + count]);
                    assert_eq!(output[0], 0xa5);
                    assert!(output[1 + count..].iter().all(|byte| *byte == 0xa5));
                }
            }
        }
    }

    #[test]
    fn segmented_windows_do_not_add_total_lengths() {
        let mut output = [0; 2];
        let mut window = ReadWindow::new(usize::MAX, &mut output);
        assert!(window.take(usize::MAX - 1).1.is_empty());
        let (start, dest) = window.take(4);
        assert_eq!(start, 1);
        assert_eq!(dest.len(), 2);
        assert!(window.take(usize::MAX).1.is_empty());
    }

    struct Reader {
        offset: u32,
        limit: usize,
        reads: usize,
        closes: usize,
        error: Option<StatusWord>,
        excessive: bool,
    }
    impl Reader {
        fn new(offset: u32, limit: usize) -> Self {
            Self {
                offset,
                limit,
                reads: 0,
                closes: 0,
                error: None,
                excessive: false,
            }
        }
    }
    impl Source for Reader {
        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<usize, ReadError> {
            assert_eq!(offset, self.offset);
            assert!(!out.is_empty());
            assert_eq!(self.closes, 0);
            self.reads += 1;
            out.fill(0x5a);
            if let Some(sw) = self.error {
                return Err(ReadError(sw));
            }
            let n = if self.excessive {
                out.len() + 1
            } else {
                self.limit.min(out.len())
            };
            self.offset += n as u32;
            Ok(n)
        }
        fn close(&mut self) {
            self.closes += 1;
        }
    }

    #[test]
    fn short_reads_preserve_offsets_status_and_exactly_one_close() {
        for total in [0, 1, 255, 256, 257, 4096, u32::MAX] {
            for offset in [0, total / 2, total.saturating_sub(1), total] {
                for capacity in [0, 1, 7, 256] {
                    for le in [0, 1, 255, 256, u32::MAX] {
                        for limit in [1, 17, usize::MAX] {
                            let mut source = Reader::new(offset, limit);
                            let final_sw = StatusWord::DATA_INVALID;
                            let mut response = Response {
                                pending: Some(Pending {
                                    total,
                                    offset,
                                    sw: final_sw,
                                }),
                            };
                            let mut out = [0xa5; 258];
                            let plan =
                                ResponsePlan::new(total, offset, le.min(capacity as u32), final_sw)
                                    .unwrap();
                            let n = (plan.length as usize).min(limit);
                            let expected =
                                ResponsePlan::new(total, offset, n as u32, final_sw).unwrap();
                            let chunk = response
                                .next(&mut source, &mut out[1..1 + capacity], le)
                                .unwrap();
                            assert_eq!(
                                chunk,
                                Chunk {
                                    len: n,
                                    sw: expected.sw
                                }
                            );
                            assert_eq!(source.reads, usize::from(plan.length != 0));
                            assert_eq!(source.offset, expected.next);
                            assert_eq!(response.active(), !expected.complete);
                            if let Some(p) = response.pending {
                                assert_eq!(p.offset, expected.next);
                            }
                            assert_eq!(source.closes, usize::from(expected.complete));
                            assert_eq!(out[0], 0xa5);
                            assert!(out[1 + capacity..].iter().all(|b| *b == 0xa5));
                            response.clear(&mut source);
                            response.clear(&mut source);
                            assert_eq!(source.closes, 1);
                        }
                    }
                }
            }
        }
        let mut response = Response::new();
        response.start(10, StatusWord::SUCCESS);
        let mut source = Reader::new(0, 3);
        for expected in [
            Chunk {
                len: 3,
                sw: StatusWord::new(0x6107).unwrap(),
            },
            Chunk {
                len: 3,
                sw: StatusWord::new(0x6104).unwrap(),
            },
            Chunk {
                len: 3,
                sw: StatusWord::new(0x6101).unwrap(),
            },
            Chunk {
                len: 1,
                sw: StatusWord::SUCCESS,
            },
        ] {
            assert_eq!(response.next(&mut source, &mut [0; 8], 8), Ok(expected));
        }
        assert_eq!((source.reads, source.closes), (4, 1));
        assert_eq!(
            response.next(&mut source, &mut [0; 8], 8),
            Err(StatusWord::COMMAND_NOT_ALLOWED)
        );
    }

    #[test]
    fn invalid_reads_wipe_requested_window_and_end_the_lease() {
        for kind in 0..3 {
            let mut source = Reader::new(0, if kind == 0 { 0 } else { 4 });
            source.excessive = kind == 1;
            source.error = (kind == 2).then_some(StatusWord::EXECUTION_ERROR);
            let mut response = Response::new();
            response.start(10, StatusWord::SUCCESS);
            let mut out = [0xa5; 8];
            let expected = source.error.unwrap_or(StatusWord::UNABLE_TO_PROCESS);
            assert_eq!(response.next(&mut source, &mut out[1..7], 4), Err(expected));
            assert_eq!(out, [0xa5, 0, 0, 0, 0, 0xa5, 0xa5, 0xa5]);
            assert!(!response.active());
            response.clear(&mut source);
            assert_eq!((source.reads, source.closes), (1, 1));
        }
    }

    #[test]
    fn start_does_not_replace_an_active_lease() {
        let mut response = Response::new();
        assert!(response.start(4, StatusWord::SUCCESS));
        assert!(!response.start(8, StatusWord::WRONG_DATA));
        assert!(response.active());
    }
}
