// SPDX-License-Identifier: Apache-2.0
//! Bounded BER tag/length/value streaming. Values are never accumulated here.
//! Up to three encoded tag bytes and two length bytes; indefinite lengths are
//! rejected. Non-minimal definite lengths remain accepted like the C helpers.
pub mod length;
use length::{Feed, LengthState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Truncated,
    Consumer,
    Failed,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    encoded: [u8; 3],
    len: u8,
}

impl Tag {
    pub fn bytes(&self) -> &[u8] {
        &self.encoded[..usize::from(self.len)]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    Start { tag: Tag, length: u16 },
    Value(&'a [u8]),
    End,
}

#[derive(Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Tag,
    Length,
    Value,
}

#[derive(Default)]
pub struct Decoder {
    tag: [u8; 3],
    tag_len: u8,
    length: LengthState,
    remaining: u16,
    phase: Phase,
    failed: bool,
}

impl Decoder {
    /// Events are provisional until the enclosing request and finish succeed.
    /// Nested constructed values are opaque; the schema owner decides nesting.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = self.feed_inner(bytes, emit);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn feed_inner(
        &mut self,
        mut bytes: &[u8],
        emit: &mut dyn FnMut(Event<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while !bytes.is_empty() {
            match self.phase {
                Phase::Tag => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    let i = usize::from(self.tag_len);
                    if i == 3 || (i == 1 && byte & 0x7f == 0) {
                        return Err(Error::Invalid);
                    }
                    self.tag[i] = byte;
                    self.tag_len += 1;
                    if (i == 0 && byte & 0x1f != 0x1f) || (i != 0 && byte & 0x80 == 0) {
                        self.phase = Phase::Length;
                    } else if self.tag_len == 3 {
                        return Err(Error::Invalid);
                    }
                }
                Phase::Length => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    match self.length.feed(byte) {
                        Feed::Invalid => return Err(Error::Invalid),
                        Feed::More => (),
                        Feed::Complete(length) => {
                            emit(Event::Start {
                                tag: Tag {
                                    encoded: self.tag,
                                    len: self.tag_len,
                                },
                                length,
                            })
                            .map_err(|_| Error::Consumer)?;
                            self.remaining = length;
                            if length == 0 {
                                emit(Event::End).map_err(|_| Error::Consumer)?;
                                self.tag_len = 0;
                                self.phase = Phase::Tag;
                            } else {
                                self.phase = Phase::Value;
                            }
                        }
                    }
                }
                Phase::Value => {
                    let n = bytes.len().min(usize::from(self.remaining));
                    emit(Event::Value(&bytes[..n])).map_err(|_| Error::Consumer)?;
                    self.remaining -= n as u16;
                    bytes = &bytes[n..];
                    if self.remaining == 0 {
                        emit(Event::End).map_err(|_| Error::Consumer)?;
                        self.tag_len = 0;
                        self.phase = Phase::Tag;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Failed)
        } else if self.phase == Phase::Tag && self.tag_len == 0 {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}

/// Write a canonical definite length. Failure leaves output unchanged.
pub fn write_length(length: u16, output: &mut [u8]) -> Result<usize, Error> {
    let [hi, lo] = length.to_be_bytes();
    let (bytes, n) = if length < 128 {
        ([lo, 0, 0], 1)
    } else if length < 256 {
        ([0x81, lo, 0x00], 2)
    } else {
        ([0x82, hi, lo], 3)
    };
    if output.len() < n {
        return Err(Error::Capacity);
    }
    output[..n].copy_from_slice(&bytes[..n]);
    Ok(n)
}

/// Cursor for protocols with single-byte tag and length fields (not BER).
/// Schema-specific exceptions can consume a raw byte explicitly.
pub struct ByteCursor<'a> {
    remaining: &'a [u8],
}
impl<'a> ByteCursor<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (value, tail) = self.remaining.split_at(n);
        self.remaining = tail;
        Ok(value)
    }
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn field(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let tag = self.byte()?;
        let len = usize::from(self.byte()?);
        Ok((tag, self.take(len)?))
    }
    pub fn peek(&self) -> Option<u8> {
        self.remaining.first().copied()
    }
    pub fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
