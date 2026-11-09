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
