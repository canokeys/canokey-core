// SPDX-License-Identifier: Apache-2.0
//! Shared incremental request framing and first-error handling. Command schemas
//! own field interpretation; this boundary preserves their exact status codes.
use super::Error;
use canokey_protocol::cbor::{self, Event};

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
    // Preserve the full 64-bit ordering even for unrecognized field labels.
    // One call boundary avoids duplicating the comparison in every schema.
    // None is an unknown label, not an absent key; callers retain it as Some(None).
    #[inline(never)]
    pub fn ordered(
        event: &canokey_protocol::cbor::Event<'_>,
        previous: &mut Option<Self>,
    ) -> Result<Option<i8>, E> {
        let key = Self::parse(event)?;
        if previous.is_some_and(|old| (key.negative, key.argument) <= (old.negative, old.argument))
        {
            return Err(E::INVALID_CBOR);
        }
        *previous = Some(key);
        Ok(key.integer())
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
