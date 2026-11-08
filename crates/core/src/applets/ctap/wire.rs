// SPDX-License-Identifier: Apache-2.0
//! CTAP/COSE assignments and PIN protocol lengths. Labels are scoped by schema.
pub(super) const RP_ID_MAX: usize = 254;
pub(super) mod cose {
    pub const ES256: i32 = -7;
    pub const EDDSA: i32 = -8;
    pub const MLDSA65: i32 = crate::ports::mldsa::DSA65.cose;
    pub const MLDSA44: i32 = crate::ports::mldsa::DSA44.cose;
    pub const CRV: i8 = -1;
    pub const X: i8 = -2;
    pub const Y: i8 = -3;
    pub const P256: i8 = 1;
}
pub(super) mod pin_protocol {
    use canokey_ctap::client_pin::{
        Protocol,
        request::{self, Command},
    };
    pub const V1: u8 = Protocol::One as u8;
    pub const V2: u8 = Protocol::Two as u8;
    pub const AES_BLOCK_BYTES: usize = canokey_ctap::client_pin::cipher::BLOCK_BYTES;
    pub const AUTH_V1_BYTES: usize = Protocol::One.auth_bytes();
    pub const AUTH_V2_BYTES: usize = Protocol::Two.auth_bytes();
    pub const PIN_HASH_BYTES: usize = request::PIN_HASH_BYTES; // left(SHA-256(PIN),16).
    pub const PADDED_PIN_BYTES: usize = request::PADDED_PIN_BYTES;
    pub const NEW_PIN_V1_BYTES: usize = PADDED_PIN_BYTES;
    pub const NEW_PIN_V2_BYTES: usize = AES_BLOCK_BYTES + PADDED_PIN_BYTES;
    pub const MIN_CODE_POINTS: u8 = 0x04;
    pub const MAX_PIN_BYTES: u8 = 63;
    pub const MAX_RETRIES: u8 = 8;
    pub const SESSION_ATTEMPTS: u8 = 0x03; // Reboot required after three bad PIN proofs.
    pub const GET_RETRIES: u8 = Command::Retries as u8;
    pub const GET_AGREEMENT: u8 = Command::Agreement as u8;
    pub const SET_PIN: u8 = Command::Set as u8;
    pub const CHANGE_PIN: u8 = Command::Change as u8;
    pub const GET_TOKEN: u8 = Command::Token as u8;
    pub const GET_TOKEN_PERMISSIONS: u8 = Command::TokenPermissions as u8;
    pub const LABEL_PROTOCOL: i8 = request::LABEL_PROTOCOL;
    pub const LABEL_SUBCOMMAND: i8 = request::LABEL_SUBCOMMAND;
    pub const LABEL_AGREEMENT: i8 = request::LABEL_AGREEMENT;
    pub const LABEL_AUTH: i8 = request::LABEL_AUTH;
    pub const LABEL_NEW_PIN: i8 = request::LABEL_NEW_PIN;
    pub const LABEL_PIN_HASH: i8 = request::LABEL_PIN_HASH;
    pub const LABEL_PERMISSIONS: i8 = request::LABEL_PERMISSIONS;
    pub const LABEL_RP_ID: i8 = request::LABEL_RP_ID;
    pub const RESPONSE_TOKEN: u8 = 0x02;
    pub const RESPONSE_RETRIES: u8 = 0x03;
    pub const PERMISSION_MAKE: u8 = request::PERMISSION_MAKE as u8;
    pub const PERMISSION_ASSERT: u8 = request::PERMISSION_ASSERT as u8;
    pub const PERMISSION_BIO: u8 = 0x08;
    pub const PERMISSION_CREDENTIALS: u8 = request::PERMISSION_CREDENTIALS as u8;
    pub const PERMISSION_RP: u8 = PERMISSION_MAKE | PERMISSION_ASSERT;
    pub const PERMISSION_MASK: u8 = 0x3f;
    pub const fn auth_bytes(protocol: u8) -> usize {
        if protocol == V1 {
            AUTH_V1_BYTES
        } else {
            AUTH_V2_BYTES
        }
    }
    pub const fn new_pin_bytes(protocol: u8) -> usize {
        if protocol == V1 {
            NEW_PIN_V1_BYTES
        } else {
            NEW_PIN_V2_BYTES
        }
    }
}
pub(super) mod config {
    pub const TOGGLE_ALWAYS_UV: u8 = 0x02;
    pub const SET_MIN_PIN: u8 = 0x03;
    pub const VENDOR_LONG_RESET: u8 = 0x04;
}
pub(super) mod management {
    pub const METADATA: u8 = 0x01;
    pub const RP_BEGIN: u8 = 0x02;
    pub const RP_NEXT: u8 = 0x03;
    pub const CREDENTIAL_BEGIN: u8 = 0x04;
    pub const CREDENTIAL_NEXT: u8 = 0x05;
    pub const DELETE: u8 = 0x06;
    pub const UPDATE_USER: u8 = 0x07;
    pub const VENDOR_METADATA_ONLY: u8 = 0x80;
    pub const VENDOR_ALGORITHM: u8 = 0x80;
    pub const USER: u8 = 0x06;
    pub const DESCRIPTOR: u8 = 0x07;
    pub const TOTAL_CREDENTIALS: u8 = 0x09;
    pub const CRED_PROTECT: u8 = 0x0a;
    pub const LARGE_BLOB_KEY: u8 = 0x0b;
    pub const THIRD_PARTY_PAYMENT: u8 = 0x0c;
}
pub(super) mod auth_data {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const AT: u8 = 0x40;
    pub const ED: u8 = 0x80;
    pub const FLAGS_OFFSET: usize = 32;
    pub const COUNTER_OFFSET: usize = FLAGS_OFFSET + 1;
    pub const HEADER_BYTES: usize = COUNTER_OFFSET + 4;
    pub const CREDENTIAL_LENGTH_OFFSET: usize = HEADER_BYTES + 16; // AAGUID16.
    pub const CREDENTIAL_OFFSET: usize = CREDENTIAL_LENGTH_OFFSET + 2;
}
pub(super) mod make_response {
    // Format/authData labels are carried by generated MAKE_HEADER.
    pub const ATTESTATION: u8 = 0x03;
    pub const LARGE_BLOB_KEY: u8 = 0x05;
}
pub(super) mod assertion_response {
    pub const CREDENTIAL: u8 = 0x01;
    pub const AUTH_DATA: u8 = 0x02;
    pub const SIGNATURE: u8 = 0x03;
    pub const USER: u8 = 0x04;
    pub const COUNT: u8 = 0x05;
    pub const LARGE_BLOB_KEY: u8 = 0x07;
}
