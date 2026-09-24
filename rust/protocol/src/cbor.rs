// SPDX-License-Identifier: Apache-2.0
//! Incremental, definite-length CBOR for CTAP. No heap or request buffer.
//! Accepts shortest integer/length encodings, UTF-8 text, bytes, arrays, maps,
//! booleans and null. Tags, floats and indefinite values are not CTAP input.
//! Map key types/order/uniqueness belong to the command schema. Events are
//! provisional until finish succeeds; consumers must not perform side effects.

pub use minicbor::{Decoder as SliceDecoder, Encoder};
pub type EncodeError = minicbor::encode::Error<minicbor::encode::write::EndOfSlice>;

const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Limit,
    Truncated,
    Consumer,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    Unsigned(u64),
    /// The CBOR argument n represents the integer -1-n.
    Negative(u64),
    Bytes(u16),
    Text(u16),
    Array(u16),
    Map(u16),
    Bool(bool),
    Null,
    Data(&'a [u8]),
    /// Closes a byte/text string, array or map (including empty ones).
    End,
}

pub struct Decoder {
    head: [u8; 9],
    head_len: u8,
    pending: [u16; MAX_DEPTH + 1],
    depth: usize,
    body: u16,
    text: bool,
    utf8: Utf8,
    budget: u16,
    limit: u16,
    failed: bool,
}
impl Decoder {
    /// byte_limit bounds total input and declared collection/string lengths.
    pub const fn new(byte_limit: u16) -> Self {
        let mut pending = [0; MAX_DEPTH + 1];
        pending[0] = 1; // Exactly one top-level item.
        Self {
            head: [0; 9],
            head_len: 0,
            pending,
            depth: 0,
            body: 0,
            text: false,
            utf8: Utf8::new(),
            budget: byte_limit,
            limit: byte_limit,
            failed: false,
        }
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.feed_at(bytes, &mut |event, _| emit(event))
    }
    /// Event offsets are the number of input bytes consumed. A container's
    /// closing offset delimits its exact wire encoding for authenticated CBOR.
    pub fn feed_at(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>, u16) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = self.feed_inner(bytes, emit);
        self.failed = result.is_err();
        result
    }
    fn feed_inner(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>, u16) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if bytes.len() > usize::from(self.budget) {
            return Err(Error::Limit);
        }
        while !bytes.is_empty() {
            if self.body != 0 {
                let n = bytes.len().min(usize::from(self.body));
                if self.text {
                    self.utf8.feed(&bytes[..n])?;
                }
                self.body -= n as u16;
                self.budget -= n as u16;
                emit(Event::Data(&bytes[..n]), self.limit - self.budget)
                    .map_err(|_| Error::Consumer)?;
                bytes = &bytes[n..];
                if self.body == 0 {
                    if self.text && self.utf8.len != 0 {
                        return Err(Error::Invalid);
                    }
                    emit(Event::End, self.limit - self.budget).map_err(|_| Error::Consumer)?;
                    self.close_containers(emit)?;
                }
                continue;
            }
            if self.pending[self.depth] == 0 {
                return Err(Error::Invalid); // Trailing top-level item.
            }
            let head = self.read_header(bytes[0])?;
            self.budget -= 1;
            bytes = &bytes[1..];
            if let Some((major, value)) = head {
                self.pending[self.depth] -= 1;
                let event = self.start_value(major, value)?;
                emit(event, self.limit - self.budget).map_err(|_| Error::Consumer)?;
                if self.body == 0 {
                    if major == 2 || major == 3 {
                        emit(Event::End, self.limit - self.budget).map_err(|_| Error::Consumer)?;
                    }
                    self.close_containers(emit)?;
                }
            }
        }
        Ok(())
    }
    #[inline(never)]
    fn read_header(&mut self, byte: u8) -> Result<Option<(u8, u64)>, Error> {
        self.head[usize::from(self.head_len)] = byte;
        self.head_len += 1;
        // Buffer one complete header before calling minicbor. Framing only
        // needs the encoded width; minicbor still decodes and validates it.
        let width = match self.head[0] & 0x1f {
            0..=23 => 1,
            24 => 2,
            25 => 3,
            26 => 5,
            27 => 9,
            _ => return Err(Error::Invalid),
        };
        if self.head_len < width {
            return Ok(None);
        }
        let major = self.head[0] >> 5;
        if major == 2 || major == 3 {
            // String lengths use the same argument encoding as unsigned integers.
            // Normalize only the major type so upstream minicbor can decode the
            // length without requiring the streamed payload in this header buffer.
            self.head[0] &= 0x1f;
        }
        let mut decoder = minicbor::Decoder::new(&self.head[..usize::from(self.head_len)]);
        let result = match major {
            0 | 2 | 3 => decoder.u64(),
            1 => decoder.int().map(|n| (-1 - i128::from(n)) as u64),
            4 | 5 => {
                let count = if major == 4 {
                    decoder.array()
                } else {
                    decoder.map()
                };
                Ok(count.map_err(|_| Error::Invalid)?.ok_or(Error::Invalid)?)
            }
            7 if self.head[0] == 0xf4 || self.head[0] == 0xf5 => {
                decoder.bool().map(|b| 20 + u64::from(b))
            }
            7 if self.head[0] == 0xf6 => decoder.null().map(|()| 22),
            _ => return Err(Error::Invalid),
        };
        let value = match result {
            Ok(value) => value,
            Err(_) => return Err(Error::Invalid),
        };
        // CTAP requires shortest arguments; minicbor intentionally accepts all
        // valid CBOR widths, so this protocol policy belongs in the adapter.
        let shortest = match value {
            0..=23 => 1,
            24..=0xff => 2,
            0x100..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9,
        };
        if usize::from(self.head_len) != shortest {
            return Err(Error::Invalid);
        }
        self.head_len = 0;
        Ok(Some((major, value)))
    }
    fn start_value(&mut self, major: u8, value: u64) -> Result<Event<'static>, Error> {
        match major {
            0 => Ok(Event::Unsigned(value)),
            1 => Ok(Event::Negative(value)),
            2..=5 => {
                let count = u16::try_from(value).map_err(|_| Error::Limit)?;
                let children = if major == 5 {
                    count.checked_mul(2).ok_or(Error::Limit)?
                } else {
                    count
                };
                if children > self.budget {
                    return Err(Error::Limit);
                }
                if major < 4 {
                    self.body = count;
                    self.text = major == 3;
                    self.utf8 = Utf8::new();
                    Ok(if self.text {
                        Event::Text(count)
                    } else {
                        Event::Bytes(count)
                    })
                } else {
                    if self.depth == MAX_DEPTH {
                        return Err(Error::Limit);
                    }
                    self.depth += 1;
                    self.pending[self.depth] = children;
                    Ok(if major == 4 {
                        Event::Array(count)
                    } else {
                        Event::Map(count)
                    })
                }
            }
            7 if value == 20 || value == 21 => Ok(Event::Bool(value == 21)),
            7 if value == 22 => Ok(Event::Null),
            _ => Err(Error::Invalid),
        }
    }
    fn close_containers(
        &mut self,
        emit: &mut dyn FnMut(Event<'_>, u16) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while self.depth != 0 && self.pending[self.depth] == 0 {
            emit(Event::End, self.limit - self.budget).map_err(|_| Error::Consumer)?;
            self.depth -= 1;
        }
        Ok(())
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Failed)
        } else if self.head_len != 0 || self.body != 0 || self.depth != 0 || self.pending[0] != 0 {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }
}

// Retain only an incomplete UTF-8 code point across transport boundaries.
// The standard library validates all encoding rules, including overlong forms.
struct Utf8 {
    tail: [u8; 4],
    len: usize,
}
impl Utf8 {
    const fn new() -> Self {
        Self {
            tail: [0; 4],
            len: 0,
        }
    }
    fn feed(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while self.len != 0 && !bytes.is_empty() {
            self.tail[self.len] = bytes[0];
            self.len += 1;
            bytes = &bytes[1..];
            match core::str::from_utf8(&self.tail[..self.len]) {
                Ok(_) => self.len = 0,
                Err(error) if error.error_len().is_none() => (),
                Err(_) => return Err(Error::Invalid),
            }
        }
        match core::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() => {
                let tail = &bytes[error.valid_up_to()..];
                self.tail[..tail.len()].copy_from_slice(tail);
                self.len = tail.len();
                Ok(())
            }
            Err(_) => Err(Error::Invalid),
        }
    }
}
