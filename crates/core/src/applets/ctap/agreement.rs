// SPDX-License-Identifier: Apache-2.0
//! Product error mapping for the portable incremental COSE agreement parser.
use super::Status;
pub(super) type Parser = canokey_ctap::request::agreement::Parser<Status>;
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use canokey_protocol::cbor::{Decoder, Error, Event};
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
            match parser.event(&event, &mut coordinates, policy) {
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
