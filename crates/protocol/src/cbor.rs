// SPDX-License-Identifier: Apache-2.0
//! Incremental, definite-length CBOR for CTAP. No heap or request buffer.
//! Accepts shortest integer/length encodings, UTF-8 text, bytes, arrays, maps,
//! booleans and null. Legacy byte-string widths require explicit opt-in.
//! Tags, floats and indefinite values are not CTAP input.
//! Map key types/order/uniqueness belong to the command schema. Events are
//! provisional until finish succeeds; consumers must not perform side effects.

/// Bounded CTAP consumers translate decoder failures into protocol status codes;
/// they do not retain diagnostic strings or byte positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

/// Cursor over a contiguous input slice. Accepts every definite-length
/// encoding width (shortest form is enforced only by the incremental Decoder),
/// rejects indefinite lengths, and bounds every skip by the remaining input.
pub struct SliceDecoder<'a> {
    input: &'a [u8],
}

impl<'a> SliceDecoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Consume one header, returning (major type, argument).
    fn header(&mut self) -> Result<(u8, u64), DecodeError> {
        let (&first, _) = self.input.split_first().ok_or(DecodeError)?;
        let (major, info) = (first >> 5, first & 0x1f);
        let width = match info {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(DecodeError),
        };
        if self.input.len() < 1 + width {
            return Err(DecodeError);
        }
        let mut value = 0u64;
        if width == 0 {
            value = u64::from(info);
        } else {
            for &byte in &self.input[1..1 + width] {
                value = value << 8 | u64::from(byte);
            }
        }
        self.input = &self.input[1 + width..];
        Ok((major, value))
    }

    fn bytes_of(&mut self, major: u8) -> Result<&'a [u8], DecodeError> {
        let (m, len) = self.header()?;
        if m != major {
            return Err(DecodeError);
        }
        let len = usize::try_from(len).map_err(|_| DecodeError)?;
        if self.input.len() < len {
            return Err(DecodeError);
        }
        let (value, rest) = self.input.split_at(len);
        self.input = rest;
        Ok(value)
    }

    pub fn map(&mut self) -> Result<Option<u64>, DecodeError> {
        if self.input.first() == Some(&0xbf) {
            self.input = &self.input[1..];
            return Ok(None);
        }
        let (major, value) = self.header()?;
        if major != 5 {
            return Err(DecodeError);
        }
        Ok(Some(value))
    }
    #[inline(never)]
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let (major, value) = self.header()?;
        if major != 0 {
            return Err(DecodeError);
        }
        Ok(value)
    }
    #[inline(never)]
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.input.split_first() {
            Some((&0xf4, rest)) => {
                self.input = rest;
                Ok(false)
            }
            Some((&0xf5, rest)) => {
                self.input = rest;
                Ok(true)
            }
            _ => Err(DecodeError),
        }
    }
    #[inline(never)]
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        self.bytes_of(2)
    }
    #[inline(never)]
    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        core::str::from_utf8(self.bytes_of(3)?).map_err(|_| DecodeError)
    }
    #[inline(never)]
    pub fn skip(&mut self) -> Result<(), DecodeError> {
        self.skip_value(0)
    }
    fn skip_value(&mut self, depth: usize) -> Result<(), DecodeError> {
        if depth >= MAX_DEPTH {
            return Err(DecodeError);
        }
        let (major, value) = self.header()?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                let len = usize::try_from(value).map_err(|_| DecodeError)?;
                if self.input.len() < len {
                    return Err(DecodeError);
                }
                self.input = &self.input[len..];
                Ok(())
            }
            4..=6 => {
                let items = match major {
                    4 => value,
                    5 => value.checked_mul(2).ok_or(DecodeError)?,
                    _ => 1,
                };
                for _ in 0..items {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(DecodeError),
        }
    }
}

/// Card responses only need to distinguish success from exhausted output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError;

macro_rules! encode_unsigned {
    ($($method:ident($ty:ty)),* $(,)?) => {$(
        #[inline(never)]
        pub fn $method(&mut self, value: $ty) -> &mut Self {
            self.header(0, u64::from(value))
        }
    )*};
}
macro_rules! encode_signed {
    ($($method:ident($ty:ty)),* $(,)?) => {$(
        #[inline(never)]
        pub fn $method(&mut self, value: $ty) -> &mut Self {
            // For v < 0 the CBOR argument is -1-v, i.e. !v in two's complement.
            let (major, arg) = if value >= 0 { (0, value as u64) } else { (1, !value as u64) };
            self.header(major, arg)
        }
    )*};
}

/// Shortest-form encoder over a caller-owned buffer. The remaining unwritten
/// tail is the writer state, so `writer().len()` is the capacity left.
/// Writes latch the first capacity error. Call `finish()` before publishing any
/// result; keeping the error inside the encoder shares failure handling across
/// all fields of a response without weakening individual write bounds checks.
pub struct Encoder<W> {
    output: W,
    failed: bool,
}

impl<'a> Encoder<&'a mut [u8]> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            failed: false,
        }
    }

    /// Check the complete response before publishing it or using its bytes.
    /// Once a write fails, subsequent writes leave both the buffer and cursor
    /// unchanged. Intermediate cursor reads are valid only if this succeeds.
    pub fn finish(&self) -> Result<(), EncodeError> {
        if self.failed {
            Err(EncodeError)
        } else {
            Ok(())
        }
    }

    pub fn writer(&self) -> &&'a mut [u8] {
        &self.output
    }

    fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        if self.failed || self.output.len() < bytes.len() {
            self.failed = true;
            return self;
        }
        let tail = core::mem::take(&mut self.output);
        tail[..bytes.len()].copy_from_slice(bytes);
        self.output = &mut tail[bytes.len()..];
        self
    }

    /// Append one shortest-form item header: major type in the top 3 bits.
    fn header(&mut self, major: u8, value: u64) -> &mut Self {
        let mut head = [0u8; 9];
        let mt = major << 5;
        let n = if value < 24 {
            head[0] = mt | value as u8;
            1
        } else if value <= 0xff {
            head[0] = mt | 24;
            head[1] = value as u8;
            2
        } else if value <= 0xffff {
            head[0] = mt | 25;
            head[1..3].copy_from_slice(&(value as u16).to_be_bytes());
            3
        } else if value <= 0xffff_ffff {
            head[0] = mt | 26;
            head[1..5].copy_from_slice(&(value as u32).to_be_bytes());
            5
        } else {
            head[0] = mt | 27;
            head[1..9].copy_from_slice(&value.to_be_bytes());
            9
        };
        self.raw(&head[..n])
    }

    /// Append trusted, pre-encoded CBOR tokens (for build-generated schemas).
    /// Dynamic values must still use the typed encoding methods below.
    #[inline(never)]
    pub fn encoded(&mut self, tokens: &[u8]) -> &mut Self {
        self.raw(tokens)
    }

    encode_unsigned! { u8(u8), u16(u16), u32(u32), u64(u64) }

    encode_signed! { i8(i8), i16(i16), i32(i32), i64(i64) }

    #[inline(never)]
    pub fn map(&mut self, count: u64) -> &mut Self {
        self.header(5, count)
    }
    #[inline(never)]
    pub fn array(&mut self, count: u64) -> &mut Self {
        self.header(4, count)
    }
    #[inline(never)]
    pub fn bytes_len(&mut self, len: u64) -> &mut Self {
        self.header(2, len)
    }
    #[inline(never)]
    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.raw(&[0xf4 | u8::from(value)])
    }
    #[inline(never)]
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.header(2, value.len() as u64).raw(value)
    }
    #[inline(never)]
    pub fn str(&mut self, value: &str) -> &mut Self {
        self.header(3, value.len() as u64).raw(value.as_bytes())
    }
}

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
    end_string: bool,
    utf8: Utf8,
    budget: u16,
    limit: u16,
    failed: bool,
    wide_bytes: bool,
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
            end_string: false,
            utf8: Utf8::new(),
            budget: byte_limit,
            limit: byte_limit,
            failed: false,
            wide_bytes: false,
        }
    }
    /// Preserve legacy definite byte-string widths without relaxing other types.
    pub const fn with_wide_byte_lengths(mut self) -> Self {
        self.wide_bytes = true;
        self
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
        let mut input = bytes;
        while let Some(event) = self.next_event(&mut input)? {
            if emit(event, self.position()).is_err() {
                self.failed = true;
                return Err(Error::Consumer);
            }
        }
        Ok(())
    }

    /// Pull one event and advance the caller's fragment. Keep calling with the
    /// same fragment until None, even after it becomes empty: string/container
    /// End events may still be pending. No request bytes are retained.
    /// A failed decoder never emits another event, including on a new fragment.
    pub fn next_event<'a>(&mut self, bytes: &mut &'a [u8]) -> Result<Option<Event<'a>>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = self.next_inner(bytes);
        self.failed = result.is_err();
        result
    }

    pub fn position(&self) -> u16 {
        self.limit - self.budget
    }

    #[inline(never)]
    fn next_inner<'a>(&mut self, bytes: &mut &'a [u8]) -> Result<Option<Event<'a>>, Error> {
        // Reject an oversized fragment before delivering any of its events,
        // just as feed_at does. Remaining bytes and budget advance together.
        if bytes.len() > usize::from(self.budget) {
            return Err(Error::Limit);
        }
        loop {
            if self.end_string {
                if self.text && self.utf8.len != 0 {
                    return Err(Error::Invalid);
                }
                self.end_string = false;
                return Ok(Some(Event::End));
            }
            if self.body == 0 && self.depth != 0 && self.pending[self.depth] == 0 {
                self.depth -= 1;
                return Ok(Some(Event::End));
            }
            if bytes.is_empty() {
                return Ok(None);
            }
            if self.body != 0 {
                let n = bytes.len().min(usize::from(self.body));
                let (value, rest) = bytes.split_at(n);
                if self.text {
                    self.utf8.feed(value)?;
                }
                self.body -= n as u16;
                self.budget -= n as u16;
                *bytes = rest;
                self.end_string = self.body == 0;
                return Ok(Some(Event::Data(value)));
            }
            if self.pending[self.depth] == 0 {
                return Err(Error::Invalid); // Trailing top-level item.
            }
            let head = self.read_header(bytes[0])?;
            self.budget -= 1;
            *bytes = &bytes[1..];
            if let Some((major, value)) = head {
                self.pending[self.depth] -= 1;
                let event = self.start_value(major, value)?;
                self.end_string = (major == 2 || major == 3) && self.body == 0;
                return Ok(Some(event));
            }
        }
    }
    #[inline(never)]
    fn read_header(&mut self, byte: u8) -> Result<Option<(u8, u64)>, Error> {
        self.head[usize::from(self.head_len)] = byte;
        self.head_len += 1;
        // Buffer one complete header before decoding. Framing only
        // needs the encoded width; the argument is decoded and validated below.
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
        if major > 5 && !(major == 7 && matches!(self.head[0], 0xf4..=0xf6)) {
            return Err(Error::Invalid);
        }
        // All supported major types share the unsigned argument representation.
        // For negative integers this is n in -1-n, not a signed Rust integer.
        // The argument is the big-endian header bytes after the first byte;
        // payload/container policy is handled by start_value below.
        let mut value = 0u64;
        if self.head_len == 1 {
            value = u64::from(self.head[0] & 0x1f);
        } else {
            for &byte in &self.head[1..usize::from(self.head_len)] {
                value = value << 8 | u64::from(byte);
            }
        }
        // CTAP requires shortest arguments, so width policy belongs in the adapter.
        let shortest = match value {
            0..=23 => 1,
            24..=0xff => 2,
            0x100..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9,
        };
        if usize::from(self.head_len) != shortest && !(major == 2 && self.wide_bytes) {
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
    pub fn finish(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Failed)
        } else if self.head_len != 0
            || self.body != 0
            || self.end_string
            || self.depth != 0
            || self.pending[0] != 0
        {
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
