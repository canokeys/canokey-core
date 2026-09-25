// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP response schemas. Fixed tokens are encoded on the build host.
use super::{credential, resident, settings::Sm2};
use crate::ports::alg;
use canokey_protocol::cbor::{EncodeError, Encoder};

include!(concat!(env!("OUT_DIR"), "/ctap_response.rs"));

// These boundaries share the schema across authentication and management.
#[inline(never)]
pub(super) fn descriptor(e: &mut Encoder<&mut [u8]>, id: &[u8]) -> Result<(), EncodeError> {
    e.encoded(DESCRIPTOR).bytes(id).encoded(PUBLIC_KEY_TYPE);
    e.finish()
}

#[inline(never)]
pub(super) fn user(
    e: &mut Encoder<&mut [u8]>,
    entry: &resident::Entry<'_>,
    details: bool,
) -> Result<(), EncodeError> {
    let name = details && !entry.name.is_empty();
    let display = details && !entry.display.is_empty();
    e.map(1 + u64::from(name) + u64::from(display))
        .encoded(USER_ID)
        .bytes(entry.user);
    if name {
        e.encoded(USER_NAME)
            .str(core::str::from_utf8(entry.name).unwrap_or_default());
    }
    if display {
        e.encoded(USER_DISPLAY)
            .str(core::str::from_utf8(entry.display).unwrap_or_default());
    }
    e.finish()
}

// Classic and streamed PQ management responses share the same envelope.
// Keep these schemas out of line so both callers use one encoder path.
#[inline(never)]
pub(super) fn management_header(
    e: &mut Encoder<&mut [u8]>,
    entry: &resident::Entry<'_>,
    first: bool,
    has_blob_key: bool,
) -> Result<(), EncodeError> {
    e.map(5 + u64::from(first) + u64::from(has_blob_key)).u8(6);
    user(e, entry, true)?;
    e.u8(7);
    descriptor(e, entry.id)
}

#[inline(never)]
pub(super) fn management_tail(
    e: &mut Encoder<&mut [u8]>,
    id: &credential::Id,
    total: Option<u8>,
    blob_key: Option<&[u8]>,
) -> Result<(), EncodeError> {
    if let Some(total) = total {
        e.u8(9).u8(total);
    }
    e.u8(10).u8(id[1] & 3);
    if let Some(key) = blob_key {
        e.u8(11).bytes(key);
    }
    e.u8(12).bool(id[1] & credential::THIRD_PARTY_PAYMENT != 0);
    e.finish()
}

pub(super) fn mldsa_public_header(e: &mut Encoder<&mut [u8]>) -> Result<(), EncodeError> {
    e.encoded(COSE_MLDSA65)
        .bytes_len(super::pq::PUBLIC_BYTES as u64);
    e.finish()
}

pub(super) fn key_agreement(e: &mut Encoder<&mut [u8]>, public: &[u8]) -> Result<(), EncodeError> {
    e.encoded(KEY_AGREEMENT)
        .bytes(&public[..32])
        .i8(-3)
        .bytes(&public[32..64]);
    e.finish()
}

pub(super) fn public_key(
    e: &mut Encoder<&mut [u8]>,
    algorithm: u8,
    sm2: Sm2,
    public: &[u8],
) -> Result<(), EncodeError> {
    if algorithm == alg::MLDSA65 {
        e.encoded(COSE_MLDSA65).bytes(public);
    } else if algorithm != alg::ED25519 {
        e.encoded(COSE_EC2)
            .i32(credential::cose_algorithm(algorithm, sm2))
            .i8(-1)
            .i32(if algorithm == alg::SM2 { sm2.curve } else { 1 })
            .i8(-2)
            .bytes(&public[..32])
            .i8(-3)
            .bytes(&public[32..64]);
    } else {
        e.encoded(COSE_ED25519).bytes(&public[..32]);
    }
    e.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(expected: &[u8], encode: impl Fn(&mut Encoder<&mut [u8]>) -> Result<(), EncodeError>) {
        let mut output = [0xa5; 2048];
        let mut e = Encoder::new(&mut output[..expected.len()]);
        encode(&mut e).unwrap();
        assert!(e.writer().is_empty());
        assert_eq!(&output[..expected.len()], expected);
        for size in 0..expected.len() {
            output.fill(0xa5);
            let mut e = Encoder::new(&mut output[1..1 + size]);
            assert_eq!(encode(&mut e), Err(EncodeError));
            assert_eq!(output[0], 0xa5);
            assert!(output[1 + size..].iter().all(|b| *b == 0xa5));
        }
    }

    #[test]
    fn public_key_schemas_preserve_dynamic_identifiers_and_bounds() {
        let public = [0x5a; 1952];
        for algorithm in [alg::P256, alg::ED25519, alg::SM2, alg::MLDSA65] {
            for value in [
                i32::MIN,
                -65537,
                -257,
                -25,
                -24,
                0,
                23,
                24,
                256,
                65536,
                i32::MAX,
            ] {
                let sm2 = Sm2 {
                    curve: value,
                    algorithm: value,
                };
                let n = credential::public_length(algorithm);
                let mut expected = [0; 2048];
                let mut e = Encoder::new(&mut expected[..]);
                reference_public_key(&mut e, algorithm, sm2, &public[..n]).unwrap();
                let used = 2048 - e.writer().len();
                check(&expected[..used], |e| {
                    public_key(e, algorithm, sm2, &public[..n])
                });
            }
        }
    }

    #[test]
    fn descriptor_and_user_preserve_wire_order_and_privacy() {
        check(b"\xa2\x62id\x42AB\x64type\x6apublic-key", |e| {
            descriptor(e, b"AB")
        });
        let entry = resident::Entry {
            id: &[0; credential::ID_BYTES],
            rp_hash: &[0; 32],
            rp: b"example.org",
            user: b"AB",
            name: b"Alice",
            display: b"A",
            blob: b"",
        };
        check(b"\xa1\x62id\x42AB", |e| user(e, &entry, false));
        check(
            b"\xa3\x62id\x42AB\x64name\x65Alice\x6bdisplayName\x61A",
            |e| user(e, &entry, true),
        );
        let entry = resident::Entry { name: b"", ..entry };
        check(b"\xa2\x62id\x42AB\x6bdisplayName\x61A", |e| {
            user(e, &entry, true)
        });
        let entry = resident::Entry {
            name: b"Alice",
            display: b"",
            ..entry
        };
        check(b"\xa2\x62id\x42AB\x64name\x65Alice", |e| {
            user(e, &entry, true)
        });
        let entry = resident::Entry { name: b"", ..entry };
        check(b"\xa1\x62id\x42AB", |e| user(e, &entry, true));
    }

    #[test]
    fn management_envelope_preserves_optional_fields_and_bounds() {
        for flags in 0..=u8::MAX {
            let mut id = [0x5a; credential::ID_BYTES];
            id[1] = flags;
            let entry = resident::Entry {
                id: &id,
                rp_hash: &[0; 32],
                rp: b"example.org",
                user: b"AB",
                name: b"Alice",
                display: b"A",
                blob: b"",
            };
            for total in [None, Some(0), Some(23), Some(24), Some(100)] {
                for blob_key in [None, Some(&[0x42; 32][..])] {
                    let mut expected = [0; 256];
                    let mut e = Encoder::new(&mut expected[..]);
                    // Previous schema, encoded independently of the shared helpers.
                    e.map(5 + u64::from(total.is_some()) + u64::from(blob_key.is_some()))
                        .u8(6)
                        .map(3)
                        .str("id")
                        .bytes(b"AB")
                        .str("name")
                        .str("Alice")
                        .str("displayName")
                        .str("A")
                        .u8(7)
                        .map(2)
                        .str("id")
                        .bytes(&id)
                        .str("type")
                        .str("public-key")
                        .finish()
                        .unwrap();
                    // Key 8 is the insertion point for either COSE representation.
                    let boundary = 256 - e.writer().len();
                    if let Some(total) = total {
                        e.u8(9).u8(total).finish().unwrap();
                    }
                    e.u8(10).u8(flags & 3).finish().unwrap();
                    if let Some(key) = blob_key {
                        e.u8(11).bytes(key).finish().unwrap();
                    }
                    e.u8(12)
                        .bool(flags & credential::THIRD_PARTY_PAYMENT != 0)
                        .finish()
                        .unwrap();
                    let used = 256 - e.writer().len();
                    check(&expected[..used], |e| {
                        let capacity = e.writer().len();
                        management_header(e, &entry, total.is_some(), blob_key.is_some())?;
                        assert_eq!(capacity - e.writer().len(), boundary);
                        management_tail(e, &id, total, blob_key)
                    });
                }
            }
        }
    }

    #[test]
    fn attestation_fragments_preserve_wire_tokens_and_bounds() {
        for (tokens, expected) in [
            (MAKE_HEADER, &b"\xa3\x01\x66packed\x02"[..]),
            (SELF_ATTESTATION, &b"\xa2\x63alg"[..]),
            (ATTESTATION, &b"\xa3\x63alg\x26\x63sig"[..]),
            (CERTIFICATE, &b"\x63x5c\x81"[..]),
        ] {
            check(expected, |e| e.encoded(tokens).finish());
        }
    }

    #[test]
    fn streamed_public_and_agreement_headers_match_cose() {
        check(
            b"\xa4\x01\x07\x03\x38\x30\x20\x06\x21\x59\x07\xa0",
            mldsa_public_header,
        );
        let mut expected = [0; 80];
        let prefix = b"\xa1\x01\xa5\x01\x02\x03\x38\x18\x20\x01\x21\x58\x20";
        expected[..prefix.len()].copy_from_slice(prefix);
        expected[prefix.len()..prefix.len() + 32].fill(0x5a);
        expected[prefix.len() + 32..prefix.len() + 35].copy_from_slice(b"\x22\x58\x20");
        expected[prefix.len() + 35..].fill(0x5a);
        check(&expected, |e| key_agreement(e, &[0x5a; 64]));
    }
    fn reference_public_key(
        e: &mut Encoder<&mut [u8]>,
        algorithm: u8,
        sm2: Sm2,
        public: &[u8],
    ) -> Result<(), canokey_protocol::cbor::EncodeError> {
        if algorithm == alg::MLDSA65 {
            e.map(4)
                .u8(1)
                .u8(7)
                .u8(3)
                .i8(-49)
                .i8(-1)
                .u8(6)
                .i8(-2)
                .bytes(public);
        } else if algorithm != alg::ED25519 {
            e.map(5)
                .u8(1)
                .u8(2)
                .u8(3)
                .i32(credential::cose_algorithm(algorithm, sm2))
                .i8(-1)
                .i32(if algorithm == alg::SM2 { sm2.curve } else { 1 })
                .i8(-2)
                .bytes(&public[..32])
                .i8(-3)
                .bytes(&public[32..64]);
        } else {
            e.map(4)
                .u8(1)
                .u8(1)
                .u8(3)
                .i8(-8)
                .i8(-1)
                .u8(6)
                .i8(-2)
                .bytes(&public[..32]);
        }
        e.finish()
    }
}
