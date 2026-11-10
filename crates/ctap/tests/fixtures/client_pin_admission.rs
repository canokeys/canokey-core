// SPDX-License-Identifier: Apache-2.0
// Shared raw ClientPIN cases for the owned and borrowed product parsers.
// CTAP 2.3 getPINToken (0x05): protocol/keyAgreement/pinHashEnc are required;
// permissions/rpId are forbidden. Unknown labels must still be skipped.
extern crate std;

pub fn legacy_token_cases() -> std::vec::Vec<(std::vec::Vec<u8>, Option<u8>)> {
    legacy_token_cases_for_point(&GENERATOR)
}

// SEC 2 P-256 generator, big-endian X || Y. Valid-point cases isolate schema
// admission; callers can substitute invalid coordinates to test crypto timing.
const GENERATOR: [u8; 64] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

pub fn invalid_points() -> [[u8; 64]; 4] {
    let infinity = [0x00; 64];
    let mut off_curve = infinity;
    off_curve[31] = 0x01;
    let mut x_out_of_field = infinity;
    x_out_of_field[..32].fill(0xff);
    x_out_of_field[63] = 0x01;
    let mut y_out_of_field = infinity;
    y_out_of_field[31] = 0x01;
    y_out_of_field[32..].fill(0xff);
    [infinity, off_curve, x_out_of_field, y_out_of_field]
}

pub fn legacy_token_cases_for_point(
    point: &[u8; 64],
) -> std::vec::Vec<(std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::status::Status;
    let mut cases = std::vec::Vec::new();
    for protocol in [0x01, 0x02] {
        for agreement in [false, true] {
            for hash in [false, true] {
                for permissions in [false, true] {
                    for rp in [false, true] {
                        for unknown in [false, true] {
                            let count = 2
                                + usize::from(agreement)
                                + usize::from(hash)
                                + usize::from(permissions)
                                + usize::from(rp)
                                + usize::from(unknown);
                            let mut bytes =
                                std::vec![0xa0 | count as u8, 0x01, protocol, 0x02, 0x05];
                            if agreement {
                                bytes.push(0x03);
                                canokey_ctap::client_pin::agreement::encode(point, |fragment| {
                                    bytes.extend_from_slice(fragment);
                                    Ok::<(), ()>(())
                                })
                                .unwrap();
                            }
                            if hash {
                                // pinHashEnc includes a 16-byte IV only for protocol 2.
                                let hash_bytes = if protocol == 0x01 { 16 } else { 32 };
                                bytes.push(0x06);
                                if hash_bytes < 24 {
                                    bytes.push(0x40 | hash_bytes as u8);
                                } else {
                                    bytes.extend_from_slice(&[0x58, hash_bytes as u8]);
                                }
                                bytes.extend_from_slice(&[0x00; 32][..hash_bytes]);
                            }
                            if permissions {
                                bytes.extend_from_slice(&[0x09, 0x01]);
                            }
                            if rp {
                                bytes.extend_from_slice(&[0x0a, 0x61, b'x']);
                            }
                            if unknown {
                                bytes.extend_from_slice(&[0x0b, 0xa1, 0x00, 0x80]);
                            }
                            let error = if !agreement || !hash {
                                Some(Status::MissingParameter as u8)
                            } else if permissions || rp {
                                Some(Status::InvalidParameter as u8)
                            } else {
                                None
                            };
                            cases.push((bytes, error));
                        }
                    }
                }
            }
        }
    }
    cases
}

/// Common standard requests and combined first errors. Native capability bits
/// are deliberately tested separately from these shared protocol fixtures.
pub fn parsing_cases() -> std::vec::Vec<(std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::status::Status;
    let mut cases = legacy_token_cases();
    for protocol in [0x01, 0x02] {
        for command in [0x03, 0x04, 0x09] {
            let mut bytes = std::vec![0xa0, 0x01, protocol, 0x02, command, 0x03];
            canokey_ctap::client_pin::agreement::encode(&GENERATOR, |fragment| {
                bytes.extend_from_slice(fragment);
                Ok::<(), ()>(())
            })
            .unwrap();
            let mut count = 3;
            for (label, length) in [
                (0x04, if protocol == 0x01 { 16 } else { 32 }),
                (0x05, if protocol == 0x01 { 64 } else { 80 }),
                (0x06, if protocol == 0x01 { 16 } else { 32 }),
            ] {
                if command == 0x09 && label != 0x06 || command == 0x03 && label == 0x06 {
                    continue;
                }
                count += 1;
                bytes.push(label);
                if length < 24 {
                    bytes.push(0x40 | length as u8);
                } else {
                    bytes.extend_from_slice(&[0x58, length as u8]);
                }
                bytes.extend_from_slice(&[label; 80][..length]);
            }
            if command == 0x09 {
                bytes.extend_from_slice(&[0x09, 0x04]);
                count += 1;
            }
            bytes[0] = 0xa0 | count;
            cases.push((bytes, None));
        }
    }
    let mut key = std::vec::Vec::new();
    canokey_ctap::client_pin::agreement::encode(&GENERATOR, |fragment| {
        key.extend_from_slice(fragment);
        Ok::<(), ()>(())
    })
    .unwrap();
    // Optional COSE member 2 is ordered between kty (1) and alg (3).
    let mut extended = key.clone();
    extended[0] = 0xa6;
    extended.splice(3..3, [0x02, 0xa1, 0x00, 0x80]);
    let mut unordered = key[..1].to_vec();
    unordered.extend_from_slice(&key[3..6]);
    unordered.extend_from_slice(&key[1..3]);
    unordered.extend_from_slice(&key[6..]);
    for (key, expected) in [
        (key, None),
        (extended, None),
        (unordered, Some(Status::InvalidCbor as u8)),
    ] {
        let mut bytes = std::vec![0xa3, 0x01, 0x02, 0x02, 0x02, 0x03];
        bytes.extend_from_slice(&key);
        cases.push((bytes, expected));
    }
    for length in [1, 254] {
        let mut bytes = std::vec![0xa2, 0x02, 0x01, 0x0a];
        if length < 24 {
            bytes.push(0x60 | length as u8);
        } else {
            bytes.extend_from_slice(&[0x78, length as u8]);
        }
        bytes.extend(std::iter::repeat_n(b'x', length));
        cases.push((bytes, None));
    }
    for (bytes, expected) in [
        (&[0xa1, 0x02, 0x01][..], None),
        (&[0xa2, 0x01, 0x02, 0x02, 0x02][..], None),
        (
            &[0xa2, 0x02, 0x01, 0x01, 0x02][..],
            Some(Status::InvalidCbor),
        ),
        (
            &[0xa2, 0x02, 0x01, 0x05, 0x40][..],
            Some(Status::MissingParameter),
        ),
        (
            &[0xa2, 0x01, 0x03, 0x02, 0x01][..],
            Some(Status::InvalidParameter),
        ),
        (
            &[0xa2, 0x01, 0x02, 0x02, 0x18, 0xff][..],
            Some(Status::InvalidSubcommand),
        ),
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x04, 0x40][..],
            Some(Status::InvalidCbor),
        ),
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x06, 0x40][..],
            Some(Status::InvalidCbor),
        ),
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x09, 0x00][..],
            Some(Status::InvalidParameter),
        ),
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x09, 0x20][..],
            Some(Status::UnauthorizedPermission),
        ),
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x60][..],
            Some(Status::InvalidParameter),
        ),
        // Header length 255 exceeds the RP limit before any text body arrives.
        (
            &[0xa3, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x78, 0xff][..],
            Some(Status::InvalidParameter),
        ),
        (
            &[
                0xa2, 0x02, 0x01, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
            ][..],
            None,
        ),
    ] {
        cases.push((bytes.into(), expected.map(|status| status as u8)));
    }
    cases
}
