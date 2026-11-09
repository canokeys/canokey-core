// SPDX-License-Identifier: Apache-2.0
//! Incremental COSE EC2 key agreement shared by clientPIN and hmac-secret.
//! The enclosing schema owns the coordinates and its length-error policy.
use super::{
    Error,
    stream::{self, Key},
};
use crate::client_pin::agreement::{COORDINATE_BYTES, Field, POINT_BYTES, REQUIRED_FIELDS};
use canokey_protocol::cbor::Event;

// Sentinel for a non-integer/unsupported-width label. It is outside the
// recognized COSE EC2 agreement labels 1, 3, -1, -2 and -3 and follows the skip path.
const COSE_KEY_MISSING: i8 = 127;

pub struct Parser<E: Error> {
    previous: Option<Key<E>>,
    key: Option<Option<i8>>,
    seen: u8,
    body: Option<(i8, usize)>,
    skip: u8,
}

impl<E: Error> Parser<E> {
    pub const fn new() -> Self {
        Self {
            previous: None,
            key: None,
            seen: 0,
            body: None,
            skip: 0,
        }
    }

    /// Called after the enclosing schema consumes the map header. Returns true
    /// when the map closes with all five required COSE fields present.
    #[inline(never)]
    pub fn event(
        &mut self,
        event: &Event<'_>,
        coordinates: &mut [u8; POINT_BYTES],
        length_error: E,
    ) -> Result<bool, E> {
        if stream::skip_cbor_event(&mut self.skip, event)? {
            return Ok(false);
        }
        if let Some((key, _)) = self.body {
            let target = if Field::decode(i64::from(key)) == Some(Field::X) {
                &mut coordinates[..COORDINATE_BYTES]
            } else {
                &mut coordinates[COORDINATE_BYTES..]
            };
            stream::consume_cbor_body(event, &mut self.body, target)?;
            return Ok(false);
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return if self.seen == REQUIRED_FIELDS {
                    Ok(true)
                } else {
                    Err(E::MISSING_PARAMETER)
                };
            }
            self.key = Some(Key::ordered(event, &mut self.previous)?);
            return Ok(false);
        };
        let key = key.unwrap_or(COSE_KEY_MISSING);
        let bit = field(key, event)?;
        if bit == 0 {
            if stream::is_cbor_container(event) {
                self.skip = 1;
            }
        } else {
            if matches!(Field::decode(i64::from(key)), Some(Field::X | Field::Y)) {
                match *event {
                    Event::Bytes(length) if usize::from(length) == COORDINATE_BYTES => {
                        self.body = Some((key, 0))
                    }
                    Event::Bytes(_) => return Err(length_error),
                    _ => return Err(E::UNEXPECTED_TYPE),
                }
            }
            self.seen |= bit;
        }
        Ok(false)
    }
}

/// Validate one member of the COSE_Key agreement map shared by clientPIN and
/// hmac-secret. Unknown optional members are ignored by the caller.
fn field<E: Error>(key: i8, event: &canokey_protocol::cbor::Event<'_>) -> Result<u8, E> {
    let Some(field) = Field::decode(i64::from(key)) else {
        return Ok(0x00);
    };
    if let Some(expected) = field.scalar() {
        if Key::<E>::parse(event)?.integer().map(i64::from) != Some(expected) {
            return Err(E::INVALID_PARAMETER);
        }
    }
    // Coordinate lengths are checked by the parser using its caller's policy.
    Ok(field.bit())
}
