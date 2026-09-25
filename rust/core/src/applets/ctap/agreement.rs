// SPDX-License-Identifier: Apache-2.0
//! Incremental COSE EC2 key agreement shared by clientPIN and hmac-secret.
//! The enclosing schema owns the coordinates and its length-error policy.
use super::{Key, Status};
use canokey_protocol::cbor::Event;

pub(super) struct Parser {
    previous: Option<Key>,
    key: Option<Option<i8>>,
    seen: u8,
    body: Option<(i8, usize)>,
    skip: u8,
}

impl Parser {
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
        event: Event<'_>,
        coordinates: &mut [u8; 64],
        length_error: Status,
    ) -> Result<bool, Status> {
        if super::skip_cbor_event(&mut self.skip, event) {
            return Ok(false);
        }
        if let Some((key, _)) = self.body {
            let target = if key == -2 {
                &mut coordinates[..32]
            } else {
                &mut coordinates[32..]
            };
            super::consume_cbor_body(event, &mut self.body, target)?;
            return Ok(false);
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return if self.seen == 0x1f {
                    Ok(true)
                } else {
                    Err(Status::MissingParameter)
                };
            }
            self.key = Some(Key::ordered(event, &mut self.previous)?);
            return Ok(false);
        };
        // No recognized COSE agreement label uses 127. Full-width labels are
        // ordered above before unrecognized ones reach this skip path.
        let key = key.unwrap_or(127);
        let bit = field(key, event)?;
        if bit == 0 {
            if super::is_cbor_container(event) {
                self.skip = 1;
            }
        } else {
            if matches!(key, -2 | -3) {
                match event {
                    Event::Bytes(32) => self.body = Some((key, 0)),
                    Event::Bytes(_) => return Err(length_error),
                    _ => return Err(Status::UnexpectedType),
                }
            }
            self.seen |= bit;
        }
        Ok(false)
    }
}

/// Validate one member of the COSE_Key agreement map shared by clientPIN and
/// hmac-secret. Unknown optional members are ignored by the caller.
fn field(key: i8, event: canokey_protocol::cbor::Event<'_>) -> Result<u8, Status> {
    let (bit, expected) = match key {
        1 => (1, Some(2)),
        3 => (2, Some(-25)),
        -1 => (4, Some(1)),
        -2 => (8, None),
        -3 => (16, None),
        _ => return Ok(0),
    };
    if let Some(expected) = expected {
        if Key::parse(event)?.integer() != Some(expected) {
            return Err(Status::InvalidParameter);
        }
    }
    // Coordinate lengths are checked by the parser using its caller's policy.
    Ok(bit)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use canokey_protocol::cbor::{Decoder, Error};
    use std::{vec, vec::Vec};

    fn key() -> Vec<u8> {
        let mut bytes = vec![0xa5, 1, 2, 3, 0x38, 24, 0x20, 1, 0x21, 0x58, 32];
        bytes.extend_from_slice(&[0x55; 32]);
        bytes.extend_from_slice(&[0x22, 0x58, 32]);
        bytes.extend_from_slice(&[0xaa; 32]);
        bytes
    }

    fn parse(bytes: &[u8], split: usize, policy: Status) -> Result<[u8; 64], Status> {
        let mut decoder = Decoder::new(1024);
        let mut parser = Parser::new();
        let mut coordinates = [0; 64];
        let mut opened = false;
        let mut closed = false;
        let mut failure = None;
        let mut consume = |event: Event<'_>| {
            if !opened {
                assert!(matches!(event, Event::Map(_)));
                opened = true;
                return Ok(());
            }
            match parser.event(event, &mut coordinates, policy) {
                Ok(done) => {
                    closed |= done;
                    Ok(())
                }
                Err(error) => {
                    failure = Some(error);
                    Err(Error::Consumer)
                }
            }
        };
        let framing = decoder
            .feed(&bytes[..split], &mut consume)
            .and_then(|_| decoder.feed(&bytes[split..], &mut consume))
            .and_then(|_| decoder.finish());
        if let Some(error) = failure {
            return Err(error);
        }
        framing.map_err(|_| Status::InvalidCbor)?;
        assert!(closed);
        Ok(coordinates)
    }

    #[test]
    fn coordinates_and_unknown_values_survive_every_split() {
        let ordinary = key();
        let mut extended = ordinary.clone();
        extended[0] = 0xa6;
        // Unknown full-width negative label, then a nested array/map/byte value.
        extended.extend_from_slice(&[
            0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0xa1, 0, 0x42, 7, 8,
        ]);
        for bytes in [ordinary, extended] {
            for split in 0..=bytes.len() {
                let coordinates = parse(&bytes, split, Status::InvalidCbor).unwrap();
                assert_eq!(&coordinates[..32], &[0x55; 32]);
                assert_eq!(&coordinates[32..], &[0xaa; 32]);
            }
        }
    }

    #[test]
    fn required_fields_order_and_caller_length_policy_are_preserved() {
        let mut missing = key();
        missing[0] = 0xa4;
        missing.truncate(43);
        let mut duplicate = key();
        duplicate[43] = 0x21;
        let mut wrong_type = key();
        wrong_type[9] = 0xf5;
        wrong_type.drain(10..43);
        let mut short = key();
        short[10] = 31;
        short.remove(11);
        for policy in [Status::InvalidCbor, Status::InvalidParameter] {
            for (bytes, expected) in [
                (&missing, Status::MissingParameter),
                (&duplicate, Status::InvalidCbor),
                (&wrong_type, Status::UnexpectedType),
                (&short, policy),
            ] {
                for split in 0..=bytes.len() {
                    assert_eq!(parse(bytes, split, policy), Err(expected));
                }
            }
        }
    }
}
