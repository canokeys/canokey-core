// SPDX-License-Identifier: Apache-2.0
// Shared raw requests for both actual product parsers. Envelope errors precede
// deferred parameter semantics; None means structurally valid, not authorized.
extern crate std;
use canokey_ctap::status::Status;
use std::{vec, vec::Vec};
pub fn cases() -> Vec<(Vec<u8>, Option<u8>)> {
    let mut cases = vec![
        (vec![0xa0], Some(Status::MissingParameter as u8)),
        (
            vec![0xa1, 0x01, 0x19, 0x01, 0x00],
            Some(Status::InvalidParameter as u8),
        ),
        (
            vec![0xa1, 0x01, 0x20],
            Some(Status::CborUnexpectedType as u8),
        ),
        (
            vec![0xa2, 0x01, 0x07, 0x02, 0x80],
            Some(Status::CborUnexpectedType as u8),
        ),
        (vec![0xa2, 0x01, 0x07, 0x02, 0xa0], None),
        (vec![0xa2, 0x01, 0x01, 0x05, 0xa1, 0x00, 0x80], None),
    ];
    // Invalid credential ID length, with/without a later bad header field.
    let params = b"\xa1\x02\xa1\x62id\x40";
    for protocol in [0x00, 0x01, 0x02, 0x03, 0x20, 0xf5] {
        let mut raw = vec![0xa3, 0x01, 0x07, 0x02];
        raw.extend_from_slice(params);
        raw.extend_from_slice(&[0x03, protocol]);
        let expected = match protocol {
            0x01 | 0x02 => Status::NoCredentials,
            0xf5 => Status::CborUnexpectedType,
            _ => Status::InvalidParameter,
        };
        cases.push((raw, Some(expected as u8)));
    }
    for length in [0, 1, 15, 16, 17, 31, 32, 33] {
        let mut raw = vec![0xa3, 0x01, 0x01, 0x03, 0x01, 0x04];
        if length < 24 {
            raw.push(0x40 | length as u8);
        } else {
            raw.extend_from_slice(&[0x58, length as u8]);
        }
        raw.resize(raw.len() + length, 0x5a);
        cases.push((
            raw,
            (!matches!(length, 16 | 32)).then_some(Status::InvalidParameter as u8),
        ));
    }
    // A missing subcommand precedes deferred parameter errors.
    let mut raw = vec![0xa1, 0x02];
    raw.extend_from_slice(params);
    cases.push((raw, Some(Status::MissingParameter as u8)));
    // Header schema errors precede malformed later fields. Unknown root labels
    // use full-width integer ordering; skipped maps impose no key ordering.
    for (bytes, expected) in [
        (
            &b"\xa2\x01\x19\x01\x00\x02"[..],
            Some(Status::InvalidParameter),
        ),
        (&b"\xa2\x01\x01\x01\x01"[..], Some(Status::InvalidCbor)),
        (&b"\xa2\x02\xa0\x01\x01"[..], Some(Status::InvalidCbor)),
        (&b"\xa2\x01\x01\x20\xf6"[..], None),
        (
            &b"\xa2\x01\x01\x1b\xff\xff\xff\xff\xff\xff\xff\xff\xf6"[..],
            None,
        ),
        (&b"\xa2\x01\x01\x05\xa2\x02\x00\x01\x00"[..], None),
        (
            &b"\xa2\x01\x01\x02\x81"[..],
            Some(Status::CborUnexpectedType),
        ),
        (&b"\xa2\x01\x01\x04\x41"[..], Some(Status::InvalidParameter)),
        (&b"\xa2\x01\x01\x04\x50"[..], Some(Status::InvalidCbor)),
        (&b"\xa2\x01\x01\x03\x20"[..], Some(Status::InvalidParameter)),
    ] {
        cases.push((bytes.to_vec(), expected.map(|value| value as u8)));
    }
    for depth in 1..=6 {
        // Unknown envelope field and unknown parameter field share the same
        // four-container skip budget, but parameter errors remain deferred.
        for parameter in [false, true] {
            let mut raw = if parameter {
                vec![0xa2, 0x01, 0x01, 0x02, 0xa1, 0x04]
            } else {
                vec![0xa2, 0x01, 0x01, 0x05]
            };
            raw.extend_from_slice(&vec![0x81; depth]);
            raw.push(0x00);
            cases.push((raw, (depth > 4).then_some(Status::InvalidCbor as u8)));
        }
    }
    // Unknown parameter maps retain their received key order for the MAC.
    cases.push((
        b"\xa2\x01\x01\x02\xa1\x04\xa2\x02\x00\x01\x00".to_vec(),
        None,
    ));
    // Parameter keys and recognized entity member keys are ordered.
    for bytes in [
        &b"\xa2\x01\x01\x02\xa2\x04\x00\x04\x00"[..],
        &b"\xa2\x01\x07\x02\xa1\x03\xa2\x64name\x60\x62id\x41x"[..],
        &b"\xa2\x01\x07\x02\xa1\x03\xa2\x62id\x41x\x62id\x41y"[..],
    ] {
        cases.push((bytes.to_vec(), Some(Status::InvalidCbor as u8)));
    }
    cases
}
