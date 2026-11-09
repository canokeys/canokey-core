// SPDX-License-Identifier: Apache-2.0
//! Shared incremental request framing and first-error handling. Command schemas
//! own field interpretation; this boundary preserves their exact status codes.
use super::Error;
use canokey_protocol::cbor::{self, Event};

/// CanoKey retains at most this many bytes of a text map key. Longer unknown
/// keys still require UTF-8 and nondecreasing length, but equal-length spellings
/// are not compared, matching the bounded streaming/C compatibility contract.
pub const TEXT_KEY_BYTES: usize = 32;

#[inline(always)]
pub(crate) fn text_key_order<E: Error>(
    seen: bool,
    previous_len: usize,
    previous: &[u8],
    length: usize,
    key: &[u8],
) -> Result<(), E> {
    if seen
        && (length < previous_len
            || (length <= TEXT_KEY_BYTES && length == previous_len && key <= previous))
    {
        return Err(E::INVALID_CBOR);
    }
    Ok(())
}

pub struct TextOrder<'a> {
    previous: Option<&'a str>,
}
impl<'a> TextOrder<'a> {
    pub const fn new() -> Self {
        Self { previous: None }
    }
    pub fn next<R: super::credential::borrowed::Reader<'a>>(
        &mut self,
        reader: &mut R,
    ) -> Result<&'a str, R::Error> {
        let key = reader.text()?;
        let previous = self.previous.unwrap_or("");
        text_key_order::<R::Error>(
            self.previous.is_some(),
            previous.len(),
            previous.as_bytes(),
            key.len(),
            key.as_bytes(),
        )?;
        self.previous = Some(key);
        Ok(key)
    }
}

pub struct Decoder<E: Error, const LIMIT: u16> {
    decoder: cbor::Decoder,
    error: Option<E>,
}

impl<E: Error, const LIMIT: u16> Decoder<E, LIMIT> {
    pub const fn new() -> Self {
        Self {
            decoder: cbor::Decoder::new(LIMIT),
            error: None,
        }
    }

    pub const fn large_blob() -> Self {
        Self {
            decoder: cbor::Decoder::new(LIMIT).with_wide_byte_lengths(),
            error: None,
        }
    }

    /// Returns false after any failure. A rejected request never re-enters its
    /// schema, and a schema error takes precedence over the generic CBOR error.
    // Borrow the event only for this synchronous callback. Its scalar/slice
    // payload need not be copied through every schema/helper call boundary.
    #[inline(never)]
    pub fn consume(
        &mut self,
        bytes: &[u8],
        fields: &mut dyn FnMut(&Event<'_>, u16) -> Result<(), E>,
    ) -> bool {
        if self.error.is_some() {
            return false;
        }
        let mut input = bytes;
        loop {
            match self.decoder.next_event(&mut input) {
                Ok(Some(event)) => {
                    if let Err(status) = fields(&event, self.decoder.position()) {
                        self.error = Some(status);
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.error = Some(E::INVALID_CBOR);
                    break;
                }
            }
        }
        self.error.is_none()
    }

    pub fn finish(&self) -> Result<(), E> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.decoder.finish().map_err(|_| E::INVALID_CBOR)
    }
}

// Integer keys sort by (negative, argument): nonnegative keys before negative.
// This is not length-first canonical CBOR ordering across encoded widths.
#[derive(Clone, Copy)]
pub struct Key<E: Error> {
    pub negative: bool,
    pub argument: u64,
    error: core::marker::PhantomData<E>,
}
impl<E: Error> Key<E> {
    /// Decode a single validated integer label without narrowing a u64 CBOR
    /// argument to i64. RFC 8949 major types 0/1 carry unsigned arguments of
    /// zero, one, two, four or eight following bytes; other types are rejected.
    pub fn borrowed<'a, R: super::credential::borrowed::Reader<'a, Error = E>>(
        reader: &mut R,
    ) -> Result<Option<i8>, E> {
        Ok(Self::borrowed_full(reader)?.integer())
    }
    pub fn borrowed_ordered<'a, R: super::credential::borrowed::Reader<'a, Error = E>>(
        reader: &mut R,
        previous: &mut Option<Self>,
    ) -> Result<Option<i8>, E> {
        Self::borrowed_full(reader)?.admit_order(previous)
    }
    fn borrowed_full<'a, R: super::credential::borrowed::Reader<'a, Error = E>>(
        reader: &mut R,
    ) -> Result<Self, E> {
        let (negative, argument) = reader.integer()?;
        Ok(Self {
            negative,
            argument,
            error: core::marker::PhantomData,
        })
    }
    pub fn borrowed_i32<'a, R: super::credential::borrowed::Reader<'a, Error = E>>(
        reader: &mut R,
    ) -> Result<Option<i32>, E> {
        Ok(Self::borrowed_full(reader)?.signed_i32())
    }
    #[inline(always)]
    pub fn signed_i32(self) -> Option<i32> {
        i32::try_from(self.argument)
            .ok()
            .map(|value| if self.negative { -1 - value } else { value })
    }
    // Preserve the full 64-bit ordering even for unrecognized field labels.
    // One call boundary avoids duplicating the comparison in every schema.
    // None is an unknown label, not an absent key; callers retain it as Some(None).
    #[inline(never)]
    pub fn ordered(
        event: &canokey_protocol::cbor::Event<'_>,
        previous: &mut Option<Self>,
    ) -> Result<Option<i8>, E> {
        Self::parse(event)?.admit_order(previous)
    }
    #[inline(always)]
    fn admit_order(self, previous: &mut Option<Self>) -> Result<Option<i8>, E> {
        if previous
            .is_some_and(|old| (self.negative, self.argument) <= (old.negative, old.argument))
        {
            return Err(E::INVALID_CBOR);
        }
        *previous = Some(self);
        Ok(self.integer())
    }
    pub fn parse(event: &canokey_protocol::cbor::Event<'_>) -> Result<Self, E> {
        match *event {
            canokey_protocol::cbor::Event::Unsigned(argument) => Ok(Self {
                negative: false,
                argument,
                error: core::marker::PhantomData,
            }),
            canokey_protocol::cbor::Event::Negative(argument) => Ok(Self {
                negative: true,
                argument,
                error: core::marker::PhantomData,
            }),
            _ => Err(E::UNEXPECTED_TYPE),
        }
    }
    pub fn integer(self) -> Option<i8> {
        let n = i8::try_from(self.argument).ok()?;
        Some(if self.negative { -1 - n } else { n })
    }
}

#[inline]
pub fn is_cbor_container(event: &canokey_protocol::cbor::Event<'_>) -> bool {
    matches!(
        event,
        canokey_protocol::cbor::Event::Map(_)
            | canokey_protocol::cbor::Event::Array(_)
            | canokey_protocol::cbor::Event::Bytes(_)
            | canokey_protocol::cbor::Event::Text(_)
    )
}

/// Consume one event while ignoring an unsupported CBOR value. The decoder
/// emits container starts and a matching End, so all extension parsers can use
/// the same depth transition rules.
pub fn skip_cbor_event<E: Error>(
    depth: &mut u8,
    event: &canokey_protocol::cbor::Event<'_>,
) -> Result<bool, E> {
    if *depth == 0 {
        return Ok(false);
    }
    // Pinned C TinyCBOR skips each unknown value with at most four nested
    // maps/arrays. Known schema nesting keeps the decoder's separate budget.
    // Strings have matching End events but cannot contain another container.
    const MAX_UNKNOWN_CONTAINERS: u8 = 4;
    if matches!(
        event,
        canokey_protocol::cbor::Event::Map(_) | canokey_protocol::cbor::Event::Array(_)
    ) && *depth >= MAX_UNKNOWN_CONTAINERS
    {
        return Err(E::INVALID_CBOR);
    }
    if is_cbor_container(event) {
        *depth = depth.saturating_add(1);
    } else if matches!(event, canokey_protocol::cbor::Event::End) {
        *depth -= 1;
    }
    Ok(true)
}

pub fn consume_cbor_body<E: Error>(
    event: &canokey_protocol::cbor::Event<'_>,
    body: &mut Option<(i8, usize)>,
    target: &mut [u8],
) -> Result<(), E> {
    let Some((key, offset)) = *body else {
        return Err(E::INTERNAL);
    };
    match *event {
        canokey_protocol::cbor::Event::Data(bytes) => {
            let end = offset.checked_add(bytes.len()).ok_or(E::INVALID_CBOR)?;
            target
                .get_mut(offset..end)
                .ok_or(E::INVALID_CBOR)?
                .copy_from_slice(bytes);
            *body = Some((key, end));
        }
        canokey_protocol::cbor::Event::End => *body = None,
        _ => return Err(E::INVALID_CBOR),
    }
    Ok(())
}
