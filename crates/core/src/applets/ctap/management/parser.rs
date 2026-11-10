// SPDX-License-Identifier: Apache-2.0
//! Product envelope offsets over the common management field parser.
use super::Status;
#[cfg(test)]
use super::credential;
pub(in crate::applets::ctap) type Parsed = canokey_ctap::management::stream::Parsed<Status>;
pub(in crate::applets::ctap) type Parser =
    canokey_ctap::management::stream::Parser<Status, { super::PREFIX }>;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::applets::ctap::{Command, envelope};
    use std::{vec, vec::Vec};

    mod matrix {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ctap/tests/fixtures/management_schema.rs"
        ));
    }
    #[test]
    fn shared_management_schema_matrix_at_every_fragment_boundary() {
        for (message, expected) in matrix::cases() {
            for split in 0..=message.len() {
                let mut parser = envelope::Parser::new(0x0a);
                parser.consume(&message[..split]);
                parser.consume(&message[split..]);
                let result = parser.finish().and_then(|command| {
                    let Command::Management(parameters) = command else {
                        panic!("management command expected");
                    };
                    parameters
                        .management
                        .fields(&parameters.message)
                        .map(|_| ())
                });
                assert_eq!(
                    result.err().map(|error| error as u8),
                    expected,
                    "split={split} raw={message:02x?}"
                );
            }
        }
    }

    #[test]
    fn borrowed_envelope_matches_actual_core_truncations_and_mutations() {
        type Reader<'a> = canokey_ctap::request::borrowed::Reader<
            'a,
            Status,
            { crate::config::CtapRequestConfig::CBOR_BYTES },
        >;
        let compare = |bytes: &[u8]| {
            let mut parser = envelope::Parser::new(0x0a);
            parser.consume(bytes);
            let actual = parser.finish().and_then(|command| {
                let Command::Management(parameters) = command else {
                    panic!("management expected");
                };
                parameters
                    .management
                    .fields(&parameters.message)
                    .map(|_| ())
            });
            let borrowed = canokey_ctap::management::borrowed::Envelope::decode::<Reader<'_>>(
                bytes,
            )
            .and_then(|envelope| {
                canokey_ctap::management::borrowed::fields::<Reader<'_>, true>(envelope.parameters)
                    .map(|_| ())
            });
            assert_eq!(actual, borrowed, "raw={bytes:02x?}");
        };
        let mut count = 0;
        for (bytes, _) in matrix::cases() {
            compare(&bytes);
            for end in 0..bytes.len() {
                compare(&bytes[..end]);
            }
            let mut mutated = bytes.clone();
            for offset in 0..bytes.len() {
                for value in [
                    0x00, 0x01, 0x17, 0x18, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xf4, 0xff,
                ] {
                    mutated[offset] = value;
                    compare(&mutated);
                    count += 1;
                }
                mutated[offset] = bytes[offset];
            }
        }
        std::println!("Actual Core management oracle: {count} mutations");
    }

    fn check(params: &[u8]) {
        let expected = super::super::parse(params);
        for leading in [false, true] {
            let mut message = if leading {
                let mut bytes = vec![0xa3, 0, 0x78, 70];
                bytes.extend_from_slice(&[b'x'; 70]);
                bytes.extend_from_slice(&[1, 7, 2]);
                bytes
            } else {
                vec![0xa2, 1, 7, 2]
            };
            message.extend_from_slice(params);
            for split in 0..=message.len() {
                let mut parser = envelope::Parser::new(0x0a);
                parser.consume(&message[..split]);
                parser.consume(&message[split..]);
                let Ok(Command::Management(p)) = parser.finish() else {
                    panic!("envelope rejected {message:?}");
                };
                assert_eq!(&p.message[p.start + envelope::PREFIX..p.len], params);
                assert_eq!(
                    p.management.fields(&p.message),
                    expected,
                    "leading={leading} split={split} params={params:?}"
                );
            }
        }
    }

    fn bytes(length: usize) -> Vec<u8> {
        let mut v = if length < 24 {
            vec![0x40 + length as u8]
        } else {
            vec![0x58, length as u8]
        };
        v.resize(v.len() + length, 0x42);
        v
    }
    #[test]
    fn semantic_offsets_match_slice_oracle_at_every_fragment_boundary() {
        let mut values = vec![
            vec![0],
            vec![0xf5],
            vec![0x60],
            vec![0x61, b'x'],
            vec![0xa0],
            vec![0x80],
        ];
        for n in [0, 1, 31, 32, 64, 65, core::mem::size_of::<credential::Id>()] {
            values.push(bytes(n));
        }
        for key in [
            vec![1],
            vec![2],
            vec![3],
            vec![0x18, 0x80],
            vec![0x20],
            vec![0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ] {
            for value in &values {
                let mut p = vec![0xa1];
                p.extend_from_slice(&key);
                p.extend_from_slice(value);
                check(&p);
            }
        }
        for entity in [2, 3] {
            for field in [
                "id",
                "type",
                "name",
                "displayName",
                "longUnknownFieldNameWithUnicode界",
            ] {
                for value in &values {
                    let mut p = vec![0xa1, entity, 0xa1];
                    if field.len() < 24 {
                        p.push(0x60 + field.len() as u8);
                    } else {
                        p.extend_from_slice(&[0x78, field.len() as u8]);
                    }
                    p.extend_from_slice(field.as_bytes());
                    p.extend_from_slice(value);
                    check(&p);
                }
            }
        }
        let mut p = vec![0xa4, 1];
        p.extend(bytes(32));
        p.extend_from_slice(&[2, 0xa2, 0x62, b'i', b'd']);
        p.extend(bytes(core::mem::size_of::<credential::Id>()));
        p.extend_from_slice(b"\x64type\x6apublic-key");
        p.extend_from_slice(
            b"\x03\xa3\x62id\x41x\x64name\x63\xe7\x95\x8c\x6bdisplayName\x60\x18\x80\xf5",
        );
        check(&p);
        for p in [
            b"\xa2\x01\x40\x01\x40".as_slice(),
            b"\xa1\x03\xa2\x64name\x60\x62id\x41x",
            b"\xa1\x03\xa2\x62id\x41x\x62id\x41y",
        ] {
            check(p);
        }
    }
    #[test]
    fn envelope_errors_precede_deferred_management_errors() {
        // Bad credential ID length precedes a later invalid protocol in the
        // bytes, but management semantics historically ran after the envelope.
        for (message, expected) in [
            (
                &b"\xa3\x01\x07\x02\xa1\x02\xa1\x62id\x40\x03\x00"[..],
                Status::InvalidParameter,
            ),
            (
                &b"\xa3\x01\x07\x02\xa1\x02\xa1\x62id\x40\x03"[..],
                Status::InvalidCbor,
            ),
            (
                &b"\xa1\x02\xa1\x02\xa1\x62id\x40"[..],
                Status::MissingParameter,
            ),
        ] {
            let mut parser = envelope::Parser::new(0x0a);
            for byte in message {
                parser.consume(core::slice::from_ref(byte));
            }
            assert!(matches!(parser.finish(), Err(error) if error == expected));
        }
    }
}
