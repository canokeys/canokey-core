// SPDX-License-Identifier: Apache-2.0
//! Incremental, definite-length CBOR for CTAP. No heap or request buffer.
//! Accepts shortest integer/length encodings, UTF-8 text, bytes, arrays, maps,
//! booleans and null. Tags, floats and indefinite values are not CTAP input.
//! Map key types/order/uniqueness belong to the command schema. Events are
//! provisional until finish succeeds; consumers must not perform side effects.

const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Limit,
    Truncated,
    Consumer,
    Failed,
}
#[derive(Debug, PartialEq, Eq)]
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
            failed: false,
        }
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
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
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
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
                emit(Event::Data(&bytes[..n])).map_err(|_| Error::Consumer)?;
                self.body -= n as u16;
                self.budget -= n as u16;
                bytes = &bytes[n..];
                if self.body == 0 {
                    if self.text && self.utf8.remaining != 0 {
                        return Err(Error::Invalid);
                    }
                    emit(Event::End).map_err(|_| Error::Consumer)?;
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
                emit(event).map_err(|_| Error::Consumer)?;
                if self.body == 0 {
                    if major == 2 || major == 3 {
                        emit(Event::End).map_err(|_| Error::Consumer)?;
                    }
                    self.close_containers(emit)?;
                }
            }
        }
        Ok(())
    }
    fn read_header(&mut self, byte: u8) -> Result<Option<(u8, u64)>, Error> {
        self.head[usize::from(self.head_len)] = byte;
        self.head_len += 1;
        let major = self.head[0] >> 5;
        let info = self.head[0] & 31;
        if major == 6 || (major == 7 && !(20..=22).contains(&info)) {
            return Err(Error::Invalid);
        }
        let length = match info {
            0..=23 => 1,
            24..=27 => 1 + (1 << (info - 24)),
            _ => return Err(Error::Invalid),
        };
        if self.head_len != length {
            return Ok(None);
        }
        let value = if info < 24 {
            u64::from(info)
        } else {
            let mut value = 0u64;
            for &byte in &self.head[1..usize::from(length)] {
                value = (value << 8) | u64::from(byte);
            }
            let minimum = [24, 256, 65536, 1u64 << 32][usize::from(info - 24)];
            if value < minimum {
                return Err(Error::Invalid);
            }
            value
        };
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
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while self.depth != 0 && self.pending[self.depth] == 0 {
            emit(Event::End).map_err(|_| Error::Consumer)?;
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

// Validate text across arbitrary USB/APDU boundaries without storing it.
struct Utf8 {
    remaining: u8,
    min: u8,
    max: u8,
}
impl Utf8 {
    const fn new() -> Self {
        Self {
            remaining: 0,
            min: 0x80,
            max: 0xbf,
        }
    }
    fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for &byte in bytes {
            if self.remaining != 0 {
                if !(self.min..=self.max).contains(&byte) {
                    return Err(Error::Invalid);
                }
                self.remaining -= 1;
                self.min = 0x80;
                self.max = 0xbf;
            } else {
                (self.remaining, self.min, self.max) = match byte {
                    0..=0x7f => (0, 0x80, 0xbf),
                    0xc2..=0xdf => (1, 0x80, 0xbf),
                    0xe0 => (2, 0xa0, 0xbf),
                    0xe1..=0xec | 0xee..=0xef => (2, 0x80, 0xbf),
                    0xed => (2, 0x80, 0x9f),
                    0xf0 => (3, 0x90, 0xbf),
                    0xf1..=0xf3 => (3, 0x80, 0xbf),
                    0xf4 => (3, 0x80, 0x8f),
                    _ => return Err(Error::Invalid),
                };
            }
        }
        Ok(())
    }
}
