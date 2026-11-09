// SPDX-License-Identifier: Apache-2.0
extern crate std;

pub fn cases() -> std::vec::Vec<(bool, std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::{response::encoding::Encoder, status::Status};
    use std::vec::Vec;
    let mut cases = Vec::new();
    for make in [false, true] {
        // The clientDataHash type is rejected at its text header; the RP text
        // instead reaches UTF-8 validation. Trailing payload cannot hide the
        // first schema error behind an up-front whole-request framing pass.
        cases.push((
            make,
            b"\xa1\x01\x61\xff".to_vec(),
            Some(if make {
                Status::CborUnexpectedType
            } else {
                Status::InvalidCbor
            } as u8),
        ));
        cases.push((
            make,
            b"\xa2\x02\x40\x01\x60".to_vec(),
            Some(if make {
                Status::CborUnexpectedType
            } else {
                Status::InvalidLength
            } as u8),
        ));
        for reverse in [false, true] {
            let mut bytes = [0x00; 128];
            let mut e = Encoder::new(&mut bytes[..]);
            e.map(2).u8(if reverse { 0x02 } else { 0x01 });
            match (make, reverse) {
                (true, true) => {
                    e.map(1).str("id").str("x");
                }
                (true, false) | (false, true) => {
                    e.bytes(&[0x42; 32]);
                }
                (false, false) => {
                    e.str("x");
                }
            }
            e.u8(0x01);
            if make {
                e.bytes(&[0x42; 32]);
            } else {
                e.str("x");
            }
            e.finish().unwrap();
            let count = 128 - e.writer().len();
            cases.push((
                make,
                bytes[..count].to_vec(),
                Some(Status::InvalidCbor as u8),
            ));
        }
        // Integer order is (negative, argument), not encoded byte length.
        for (tail, error) in [
            (&b"\x18\x18\xf6\x20\xf6"[..], None),
            (
                &b"\x20\xf6\x18\x18\xf6"[..],
                Some(Status::InvalidCbor as u8),
            ),
            (
                &b"\x18\x18\xf6\x18\x18\xf6"[..],
                Some(Status::InvalidCbor as u8),
            ),
        ] {
            let mut bytes = required(make, 2, None);
            bytes.extend_from_slice(tail);
            cases.push((make, bytes, error));
        }
        // The schema skips unknown maps without imposing key types, ordering
        // or uniqueness. All tokens remain definite, shortest and valid UTF-8.
        for value in [
            &b"\xa2\x02\x00\x01\x00"[..],
            &b"\xa2\x01\x00\x01\x00"[..],
            &b"\xa2\xf4\x00\x61x\x00"[..],
        ] {
            let mut bytes = required(make, 1, None);
            bytes.push(0x18);
            bytes.push(0x18);
            bytes.extend_from_slice(value);
            cases.push((make, bytes, None));
        }
        for depth in [3, 4, 5] {
            let mut bytes = required(make, 1, None);
            bytes.extend_from_slice(b"\x18\x18");
            bytes.extend(core::iter::repeat_n(0x81, depth));
            bytes.push(0x00);
            cases.push((
                make,
                bytes,
                (depth > 4).then_some(Status::InvalidCbor as u8),
            ));
        }
        for (length, protocol, status) in [
            (16, None, Status::MissingParameter),
            (17, Some(1), Status::PinAuthInvalid),
            (33, Some(1), Status::InvalidLength),
            (16, Some(3), Status::InvalidParameter),
        ] {
            let mut bytes = required(make, 1 + u64::from(protocol.is_some()), None);
            let mut tail = [0x00; 64];
            let mut e = Encoder::new(&mut tail[..]);
            e.u8(if make { 0x08 } else { 0x06 })
                .bytes(&[0x00; 33][..length]);
            if let Some(protocol) = protocol {
                e.u8(if make { 0x09 } else { 0x07 }).u8(protocol);
            }
            e.finish().unwrap();
            let count = 64 - e.writer().len();
            bytes.extend_from_slice(&tail[..count]);
            cases.push((make, bytes, Some(status as u8)));
        }
        // Empty algorithm arrays, foreign-only entries and values outside i32
        // produce no usable public-key algorithm before product IO.
        if make {
            for algorithms in [
                &b"\x80"[..],
                &b"\x81\xa2\x63alg\x26\x64type\x67foreign"[..],
                &b"\x81\xa2\x63alg\x1b\xff\xff\xff\xff\xff\xff\xff\xff\x64type\x6apublic-key"[..],
            ] {
                let mut bytes = required(make, 0, None);
                // The default algorithm array is the final required value.
                const ALGORITHM_ARRAY_BYTES: usize = 23;
                bytes.truncate(bytes.len() - ALGORITHM_ARRAY_BYTES);
                bytes.extend_from_slice(algorithms);
                cases.push((make, bytes, Some(Status::UnsupportedAlgorithm as u8)));
            }
        }
    }
    for user in [false, true] {
        for (long, duplicate) in [(false, true), (true, false), (true, true)] {
            let mut entity = [0x00; 256];
            let mut e = Encoder::new(&mut entity[..]);
            e.map(3).str("id");
            if user {
                e.bytes(b"u");
            } else {
                e.str("x");
            }
            let first = if long { "z".repeat(33) } else { "other".into() };
            let second = if duplicate {
                first.clone()
            } else {
                "a".repeat(33)
            };
            e.str(&first).str("metadata").str(&second).str("metadata");
            e.finish().unwrap();
            let length = 256 - e.writer().len();
            let bytes = required(true, 0, Some((user, &entity[..length])));
            cases.push((true, bytes, (!long).then_some(Status::InvalidCbor as u8)));
        }
        for depth in [4, 5] {
            let mut entity = Vec::from(&b"\xa2\x62id"[..]);
            entity.extend_from_slice(if user { b"\x41u" } else { b"\x61x" });
            entity.extend_from_slice(b"\x65other");
            entity.extend(core::iter::repeat_n(0x81, depth));
            entity.push(0x00);
            let expected = if !user {
                Status::CborUnexpectedType
            } else {
                Status::InvalidCbor
            };
            cases.push((
                true,
                required(true, 0, Some((user, &entity))),
                if user && depth == 4 {
                    None
                } else {
                    Some(expected as u8)
                },
            ));
        }
    }
    cases
}

fn required(make: bool, extra: u64, entity: Option<(bool, &[u8])>) -> std::vec::Vec<u8> {
    use canokey_ctap::response::encoding::Encoder;
    let mut buffer = [0x00; 512];
    let mut e = Encoder::new(&mut buffer[..]);
    e.map(if make { 4 } else { 2 } + extra).u8(0x01);
    if make {
        e.bytes(&[0x42; 32]);
    } else {
        e.str("x");
    }
    e.u8(0x02);
    if make {
        if let Some((false, entity)) = entity {
            e.encoded(entity);
        } else {
            e.map(1).str("id").str("x");
        }
        e.u8(0x03);
        if let Some((true, entity)) = entity {
            e.encoded(entity);
        } else {
            e.map(1).str("id").bytes(b"u");
        }
        e.u8(0x04)
            .array(1)
            .map(2)
            .str("alg")
            .i32(-7)
            .str("type")
            .str("public-key");
    } else {
        e.bytes(&[0x42; 32]);
    }
    e.finish().unwrap();
    let count = 512 - e.writer().len();
    buffer[..count].to_vec()
}
