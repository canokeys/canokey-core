// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "streaming")]
use canokey_ctap::{
    credential::{ID_BYTES, Id},
    resident::Entry,
    response::encoding::{EncodeError, Encoder},
    streaming::{Mode, reply},
};
use canokey_ports::{alg, mldsa};

// Encode complete CTAP/COSE maps independently of the framing helpers, including
// generated key bytes. This oracle checks the insertion point, not just tokens.
fn reference(
    entry: &Entry<'_>,
    cose: i32,
    public: &[u8],
    total: Option<u8>,
    blob: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut bytes = vec![0x00; 4096];
    let mut encoder = Encoder::new(&mut bytes[1..]);
    encoder
        .map(5 + u64::from(total.is_some()) + u64::from(blob.is_some()))
        .u8(0x06)
        .map(1 + u64::from(!entry.name.is_empty()) + u64::from(!entry.display.is_empty()))
        .str("id")
        .bytes(entry.user);
    if !entry.name.is_empty() {
        encoder.str("name").str(entry.name);
    }
    if !entry.display.is_empty() {
        encoder.str("displayName").str(entry.display);
    }
    encoder
        .u8(0x07)
        .map(2)
        .str("id")
        .bytes(entry.id)
        .str("type")
        .str("public-key")
        .u8(0x08)
        .map(3)
        .u8(0x01)
        .u8(0x07)
        .u8(0x03)
        .i32(cose)
        .i8(-1)
        .bytes(public);
    if let Some(total) = total {
        encoder.u8(0x09).u8(total);
    }
    encoder.u8(0x0a).u8(entry.id[1] & 0x03);
    if let Some(blob) = blob {
        encoder.u8(0x0b).bytes(blob);
    }
    encoder.u8(0x0c).bool(entry.id[1] & 0x10 != 0);
    encoder.finish().unwrap();
    let length = 4096 - encoder.writer().len();
    bytes.truncate(length);
    bytes
}

#[test]
fn public_plan_matches_complete_wire_at_every_capacity() {
    let user = [0x42; 64];
    let name = "N".repeat(64);
    let display = "D".repeat(64);
    for algorithm in [alg::MLDSA44, alg::MLDSA65] {
        let parameters = mldsa::parameters(algorithm).unwrap();
        let public: Vec<_> = (0..parameters.public_bytes).map(|i| i as u8).collect();
        for flags in [0x00, 0x03, 0x08, 0x10, 0xff] {
            let mut id: Id = [0x5a; ID_BYTES];
            id[1] = flags;
            for detailed in [false, true] {
                let entry = Entry {
                    id: &id,
                    rp_hash: &[0x33; 32],
                    rp: "example.org",
                    user: &user,
                    name: if detailed { &name } else { "" },
                    display: if detailed { &display } else { "" },
                    blob: &[],
                };
                for total in [None, Some(0), Some(23), Some(24), Some(255)] {
                    for blob in [None, Some(&[0x77; 32])] {
                        let expected = reference(&entry, parameters.cose, &public, total, blob);
                        let physical = expected.len() - public.len();
                        if detailed {
                            assert!(physical > 256);
                        }
                        for capacity in 0..=physical + 1 {
                            let mut backing = vec![0xa5; physical + 3];
                            let result = reply::public(
                                &entry,
                                algorithm,
                                &id,
                                total,
                                blob,
                                &mut backing[1..1 + capacity],
                            );
                            assert_eq!(backing[0], 0xa5);
                            assert!(backing[1 + capacity..].iter().all(|&b| b == 0xa5));
                            if capacity < physical {
                                assert!(matches!(result, Err(EncodeError)));
                                continue;
                            }
                            let (plan, length) = result.unwrap();
                            assert_eq!(length, physical);
                            assert_eq!(plan.algorithm, algorithm);
                            assert!(matches!(plan.mode, Mode::Public));
                            assert_eq!(plan.prefix, plan.public_at);
                            assert_eq!(plan.output, physical);
                            assert_eq!(plan.auth, 0);
                            assert_eq!(plan.signature_at, 0);
                            assert_eq!(plan.certificate, None);
                            assert_eq!(plan.hash_prefix, (0, 0));
                            assert_eq!(plan.hash_suffix, (0, 0));
                            let mut reconstructed = backing[1..1 + plan.public_at].to_vec();
                            reconstructed.extend_from_slice(&public);
                            reconstructed
                                .extend_from_slice(&backing[1 + plan.public_at..1 + length]);
                            assert_eq!(reconstructed, expected);
                            assert!(backing[1 + length..].iter().all(|&b| b == 0xa5));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn unsupported_algorithms_cannot_publish_a_public_plan() {
    let id = [0x00; ID_BYTES];
    let entry = Entry {
        id: &id,
        rp_hash: &[0x00; 32],
        rp: "",
        user: &[],
        name: "",
        display: "",
        blob: &[],
    };
    for algorithm in 0..=u8::MAX {
        if mldsa::parameters(algorithm).is_some() {
            continue;
        }
        let mut output = [0xa5; 768];
        assert!(reply::public(&entry, algorithm, &id, None, None, &mut output).is_err());
    }
}
