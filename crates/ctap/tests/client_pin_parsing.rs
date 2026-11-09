// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    client_pin::request::{self, PermissionPolicy, borrowed},
    status::Status,
};
#[path = "fixtures/client_pin_admission.rs"]
mod cases;
const STANDARD: PermissionPolicy = PermissionPolicy {
    supported: 0x3f,
    rejected: 0x08,
    maximum: Some(0x3f),
    protocol_two_only: 0x00,
};

#[test]
fn standard_wire_cases_use_shared_admission_and_borrow_original_encrypted_fields() {
    for (bytes, expected) in cases::parsing_cases() {
        let result = borrowed::decode::<Status, 2047>(&bytes, STANDARD);
        assert_eq!(
            result.as_ref().err().map(|error| *error as u8),
            expected,
            "bytes={bytes:02x?}"
        );
        if let Ok(parsed) = result {
            for field in [parsed.auth, parsed.new_pin, parsed.pin_hash] {
                if !field.is_empty() {
                    let offset = field.as_ptr() as usize - bytes.as_ptr() as usize;
                    assert_eq!(&bytes[offset..offset + field.len()], field);
                }
            }
        }
    }
}
#[test]
fn structurally_valid_invalid_peers_remain_crypto_work_after_complete_admission() {
    for point in cases::invalid_points() {
        for (bytes, expected) in cases::legacy_token_cases_for_point(&point) {
            let result = borrowed::decode::<Status, 2047>(&bytes, STANDARD);
            assert_eq!(result.as_ref().err().map(|error| *error as u8), expected);
            if let Ok(parsed) = result {
                assert_eq!(parsed.agreement, point);
                assert_eq!(parsed.command, request::Command::Token);
            }
        }
    }
}
#[test]
fn header_errors_precede_truncation_and_request_capacity_is_bounded() {
    for (bytes, expected) in [
        (
            &[0xa2, 0x01, 0x01, 0x04, 0x58, 0x20][..],
            Status::InvalidCbor,
        ),
        (
            &[0xa2, 0x01, 0x02, 0x05, 0x58, 0x51][..],
            Status::PinPolicyViolation,
        ),
        (
            &[0xa2, 0x02, 0x01, 0x05, 0x58, 0x50][..],
            Status::MissingParameter,
        ),
        (
            &[0xa2, 0x02, 0x01, 0x0a, 0x78, 0xff][..],
            Status::InvalidParameter,
        ),
    ] {
        assert_eq!(
            borrowed::decode::<Status, 2047>(bytes, STANDARD).err(),
            Some(expected)
        );
    }
    // {2:1,11: byte string}: an ignored field still consumes the wire limit.
    let mut bytes = std::vec![0xa2, 0x02, 0x01, 0x0b, 0x59, 0x07, 0xf9];
    bytes.resize(2048, 0x00);
    assert_eq!(
        borrowed::decode::<Status, 2047>(&bytes, STANDARD).err(),
        Some(Status::InvalidCbor)
    );
}
