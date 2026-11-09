// SPDX-License-Identifier: Apache-2.0
//! CTAP/COSE assignments and PIN protocol lengths. Labels are scoped by schema.
pub(super) const RP_ID_MAX: usize = canokey_ctap::request::credential::RP_ID_MAX;
pub(super) use canokey_ctap::response::encoding::cose;

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
    pub const MAX_RETRIES: u8 = canokey_ctap::client_pin::retry::MAX_RETRIES;
    #[cfg(test)]
    pub const GET_RETRIES: u8 = Command::Retries as u8;
    pub const GET_TOKEN: u8 = Command::Token as u8;
    pub const GET_TOKEN_PERMISSIONS: u8 = Command::TokenPermissions as u8;
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
pub(super) use canokey_ctap::management;
pub(super) use canokey_ctap::response::auth_data;
