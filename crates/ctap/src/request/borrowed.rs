// SPDX-License-Identifier: Apache-2.0
//! Borrowed values framed by the same incremental decoder as streamed CTAP.
//! Map key policy belongs to the schema; unknown values use its shared budget.
use super::{Error, credential::borrowed, stream};
use canokey_protocol::cbor::{Decoder, Event};

pub struct Reader<'a, E, const LIMIT: u16 = { u16::MAX }> {
    input: &'a [u8],
    decoder: Decoder,
    error: core::marker::PhantomData<E>,
}
impl<'a, E: Error, const LIMIT: u16> Reader<'a, E, LIMIT> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            decoder: Decoder::new(LIMIT),
            error: core::marker::PhantomData,
        }
    }
    pub fn remaining(&self) -> &'a [u8] {
        self.input
    }
    pub fn done(&self) -> bool {
        self.input.is_empty()
    }
    fn event(&mut self) -> Result<Event<'a>, E> {
        self.decoder
            .next_event(&mut self.input)
            .map_err(|_| E::INVALID_CBOR)?
            .ok_or(E::INVALID_CBOR)
    }
    #[inline(never)]
    fn head(&mut self) -> Result<Event<'a>, E> {
        // Counts delimit known maps/arrays in the borrowed schema. Their End
        // events consume no bytes but must still close the shared decoder's
        // nesting state before the next field header can be delivered.
        loop {
            let event = self.event()?;
            if !matches!(event, Event::End) {
                return Ok(event);
            }
        }
    }
    pub fn map(&mut self) -> Result<usize, E> {
        match self.head()? {
            Event::Map(count) => Ok(usize::from(count)),
            _ => Err(E::UNEXPECTED_TYPE),
        }
    }
    pub fn array(&mut self) -> Result<usize, E> {
        match self.head()? {
            Event::Array(count) => Ok(usize::from(count)),
            _ => Err(E::UNEXPECTED_TYPE),
        }
    }
    pub fn uint(&mut self) -> Result<u64, E> {
        match self.head()? {
            Event::Unsigned(value) => Ok(value),
            _ => Err(E::UNEXPECTED_TYPE),
        }
    }
    pub fn int(&mut self) -> Result<i64, E> {
        let (negative, value) = self.integer()?;
        let value = i64::try_from(value).map_err(|_| E::INVALID_CBOR)?;
        Ok(if negative { -1 - value } else { value })
    }
    pub fn integer(&mut self) -> Result<(bool, u64), E> {
        Ok(match self.head()? {
            Event::Unsigned(value) => (false, value),
            Event::Negative(value) => (true, value),
            _ => return Err(E::UNEXPECTED_TYPE),
        })
    }
    pub fn parameter_uint(&mut self) -> Result<u64, E> {
        match self.head()? {
            Event::Unsigned(value) => Ok(value),
            _ => Err(E::INVALID_PARAMETER),
        }
    }
    pub fn boolean(&mut self) -> Result<bool, E> {
        match self.head()? {
            Event::Bool(value) => Ok(value),
            _ => Err(E::UNEXPECTED_TYPE),
        }
    }
    fn body(&mut self, count: usize) -> Result<&'a [u8], E> {
        let before = self.input;
        loop {
            match self.event()? {
                Event::Data(_) => {}
                Event::End => break,
                _ => return Err(E::INVALID_CBOR),
            }
        }
        before.get(..count).ok_or(E::INVALID_CBOR)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], E> {
        self.bytes_checked(|_| Ok(()))
    }
    pub fn bytes_checked(
        &mut self,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<&'a [u8], E> {
        let Event::Bytes(count) = self.head()? else {
            return Err(E::UNEXPECTED_TYPE);
        };
        let count = usize::from(count);
        admit(count)?;
        self.body(count)
    }
    pub fn text(&mut self) -> Result<&'a str, E> {
        self.text_checked(|_| Ok(()))
    }
    pub fn text_checked(
        &mut self,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<&'a str, E> {
        let Event::Text(count) = self.head()? else {
            return Err(E::UNEXPECTED_TYPE);
        };
        let count = usize::from(count);
        admit(count)?;
        core::str::from_utf8(self.body(count)?).map_err(|_| E::INVALID_CBOR)
    }
    /// Delimit one known value without imposing key ordering on its nested maps.
    pub fn item(&mut self) -> Result<&'a [u8], E> {
        self.scan(false)
    }
    pub fn skip_unknown(&mut self) -> Result<(), E> {
        self.scan(true).map(|_| ())
    }
    #[inline(never)]
    fn scan(&mut self, unknown: bool) -> Result<&'a [u8], E> {
        let before = self.input;
        let first = self.head()?;
        if stream::is_cbor_container(&first) {
            let mut depth = 1;
            while depth != 0 {
                let event = self.event()?;
                if unknown {
                    stream::skip_cbor_event::<E>(&mut depth, &event)?;
                } else if stream::is_cbor_container(&event) {
                    depth += 1;
                } else if matches!(event, Event::End) {
                    depth -= 1;
                }
            }
        }
        let count = before.len() - self.input.len();
        Ok(&before[..count])
    }
    pub fn validate(bytes: &'a [u8]) -> Result<(), E> {
        let mut reader = Self::new(bytes);
        reader.item()?;
        if !reader.done() {
            return Err(E::INVALID_CBOR);
        }
        Ok(())
    }
}
impl<'a, E: Error, const LIMIT: u16> borrowed::Reader<'a> for Reader<'a, E, LIMIT> {
    type Error = E;
    fn new(bytes: &'a [u8]) -> Self {
        Self::new(bytes)
    }
    fn validate(bytes: &'a [u8]) -> Result<(), E> {
        Self::validate(bytes)
    }
    fn done(&self) -> bool {
        self.done()
    }
    fn remaining(&self) -> &'a [u8] {
        self.remaining()
    }
    fn map(&mut self) -> Result<usize, E> {
        self.map()
    }
    fn array(&mut self) -> Result<usize, E> {
        self.array()
    }
    fn uint(&mut self) -> Result<u64, E> {
        self.uint()
    }
    fn parameter_uint(&mut self) -> Result<u64, E> {
        self.parameter_uint()
    }
    fn int(&mut self) -> Result<i64, E> {
        self.int()
    }
    fn boolean(&mut self) -> Result<bool, E> {
        self.boolean()
    }
    fn text(&mut self) -> Result<&'a str, E> {
        self.text()
    }
    fn bytes(&mut self) -> Result<&'a [u8], E> {
        self.bytes()
    }
    fn bytes_checked(&mut self, admit: impl FnOnce(usize) -> Result<(), E>) -> Result<&'a [u8], E> {
        self.bytes_checked(admit)
    }
    fn text_checked(&mut self, admit: impl FnOnce(usize) -> Result<(), E>) -> Result<&'a str, E> {
        self.text_checked(admit)
    }
    fn integer(&mut self) -> Result<(bool, u64), E> {
        self.integer()
    }
    fn item(&mut self) -> Result<&'a [u8], E> {
        self.item()
    }
    fn skip_unknown(&mut self) -> Result<(), E> {
        self.skip_unknown()
    }
}
