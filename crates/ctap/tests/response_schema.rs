// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    credential, resident,
    response::{auth_data, encoding::*},
};
use canokey_ports::alg;

fn check(expected: &[u8], encode: impl Fn(&mut Encoder<&mut [u8]>) -> Result<(), EncodeError>) {
    for capacity in 0..=expected.len() {
        let mut output = vec![0xa5; expected.len() + 2];
        let mut encoder = Encoder::new(&mut output[1..1 + capacity]);
        let result = encode(&mut encoder);
        if capacity == expected.len() {
            assert_eq!(result, Ok(()));
            assert_eq!(&output[1..1 + capacity], expected);
        } else {
            assert_eq!(result, Err(EncodeError));
        }
        assert_eq!(output[0], 0xa5);
        assert!(output[1 + capacity..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn fixed_packed_descriptor_and_signature_tokens_have_exact_bounds() {
    check(b"\xa2\x62id\x42AB\x64type\x6apublic-key", |e| {
        descriptor(e, b"AB")
    });
    for (tokens, bytes) in [
        (MAKE_HEADER, &b"\xa3\x01\x66packed\x02"[..]),
        (SELF_ATTESTATION, &b"\xa2\x63alg"[..]),
        (ATTESTATION, &b"\xa3\x63alg\x26\x63sig"[..]),
        (CERTIFICATE, &b"\x63x5c\x81"[..]),
    ] {
        check(bytes, |e| e.encoded(tokens).finish());
    }
    check(b"\xa2\x63alg\x27\x63sig", |e| self_attestation(e, -8));
}

#[test]
fn user_fields_preserve_name_privacy_and_utf8_byte_lengths() {
    check(b"\xa1\x62id\x42AB", |e| {
        user_fields(e, b"AB", "é", "🔑", false)
    });
    check(
        b"\xa3\x62id\x42AB\x64name\x62\xc3\xa9\x6bdisplayName\x64\xf0\x9f\x94\x91",
        |e| user_fields(e, b"AB", "é", "🔑", true),
    );
    check(b"\xa2\x62id\x42AB\x6bdisplayName\x61A", |e| {
        user_fields(e, b"AB", "", "A", true)
    });
    check(b"\xa2\x62id\x42AB\x64name\x61A", |e| {
        user_fields(e, b"AB", "A", "", true)
    });
    check(b"\xa1\x62id\x42AB", |e| user_fields(e, b"AB", "", "", true));
}

#[test]
fn public_key_fragments_preserve_dynamic_cose_identifiers_and_pq_lengths() {
    let mut public = [0x5a; 64];
    public[32..].fill(0xa6);
    for identifier in [
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
        let mut reference = [0x00; 96];
        let mut e = Encoder::new(&mut reference[..]);
        e.map(5)
            .u8(1)
            .u8(2)
            .u8(3)
            .i32(identifier)
            .i8(-1)
            .i32(identifier)
            .i8(-2)
            .bytes(&public[..32])
            .i8(-3)
            .bytes(&public[32..]);
        e.finish().unwrap();
        let length = 96 - e.writer().len();
        check(&reference[..length], |e| {
            ec2(e, identifier, identifier, &public)
        });
    }
    let mut expected = b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20".to_vec();
    expected.extend_from_slice(&public[..32]);
    check(&expected, |e| ed25519(e, &public));
    check(b"\xa3\x01\x07\x03\x38\x30\x20\x59\x07\xa0", |e| {
        mldsa_public_header(e, alg::MLDSA65)
    });
    check(b"\xa3\x01\x07\x03\x38\x2f\x20\x59\x05\x20", |e| {
        mldsa_public_header(e, alg::MLDSA44)
    });
    assert_eq!(mldsa_header(alg::P256), Err(EncodeError));
}

#[test]
fn management_envelope_keeps_optional_field_order_and_credential_policy() {
    for flags in 0..=u8::MAX {
        let mut id = [0x5a; credential::ID_BYTES];
        id[credential::POLICY_OFFSET] = flags;
        let entry = resident::Entry {
            id: &id,
            rp_hash: &[0x00; 32],
            rp: "example.org",
            user: b"AB",
            name: "Alice",
            display: "A",
            blob: b"",
        };
        for total in [None, Some(0), Some(23), Some(24), Some(100)] {
            for blob_key in [None, Some(&[0x42; 32][..])] {
                let mut reference = [0x00; 256];
                let mut e = Encoder::new(&mut reference[..]);
                e.map(5 + u64::from(total.is_some()) + u64::from(blob_key.is_some()))
                    .u8(0x06)
                    .map(3)
                    .str("id")
                    .bytes(b"AB")
                    .str("name")
                    .str("Alice")
                    .str("displayName")
                    .str("A")
                    .u8(0x07)
                    .map(2)
                    .str("id")
                    .bytes(&id)
                    .str("type")
                    .str("public-key");
                if let Some(total) = total {
                    e.u8(0x09).u8(total);
                }
                e.u8(0x0a).u8(flags & 0x03);
                if let Some(key) = blob_key {
                    e.u8(0x0b).bytes(key);
                }
                e.u8(0x0c).bool(flags & 0x10 != 0x00);
                e.finish().unwrap();
                let length = 256 - e.writer().len();
                check(&reference[..length], |e| {
                    management_header(e, &entry, total.is_some(), blob_key.is_some())?;
                    management_tail(e, &id, total, blob_key)
                });
            }
        }
    }
}

#[test]
fn authenticator_data_headers_preserve_flags_offsets_and_network_order() {
    for up in [false, true] {
        for uv in [false, true] {
            for make in [false, true] {
                let mut data = [0xa5; 96];
                auth_data::header(
                    &mut data,
                    &[0x42; 32],
                    &[0x12, 0x34, 0x56, 0x78],
                    up,
                    uv,
                    make,
                );
                assert_eq!(&data[..32], &[0x42; 32]);
                assert_eq!(
                    data[32],
                    u8::from(up) | (u8::from(uv) << 2) | (u8::from(make) << 6)
                );
                assert_eq!(&data[33..37], &[0x12, 0x34, 0x56, 0x78]);
                assert!(data[37..].iter().all(|byte| *byte == 0xa5));
                auth_data::attested(&mut data, &[0x99; 16], &[0x55; 34]);
                assert_eq!(&data[37..53], &[0x99; 16]);
                assert_eq!(&data[53..55], &[0x00, 0x22]);
                assert_eq!(&data[55..89], &[0x55; 34]);
                assert!(data[89..].iter().all(|byte| *byte == 0xa5));
            }
        }
    }
}
