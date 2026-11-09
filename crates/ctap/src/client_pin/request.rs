// SPDX-License-Identifier: Apache-2.0
//! ClientPIN field admission, independent of owned/borrowed CBOR decoding.
use super::Protocol;

pub const LABEL_PROTOCOL: i8 = 0x01;
pub const LABEL_SUBCOMMAND: i8 = 0x02;
pub const LABEL_AGREEMENT: i8 = 0x03;
pub const LABEL_AUTH: i8 = 0x04;
pub const LABEL_NEW_PIN: i8 = 0x05;
pub const LABEL_PIN_HASH: i8 = 0x06;
pub const LABEL_PERMISSIONS: i8 = 0x09;
pub const LABEL_RP_ID: i8 = 0x0a;
pub const PADDED_PIN_BYTES: usize = 64;
pub const PIN_HASH_BYTES: usize = 16;
pub const PERMISSION_MAKE: u16 = 0x01;
pub const PERMISSION_ASSERT: u16 = 0x02;
pub const PERMISSION_CREDENTIALS: u16 = 0x04;
pub const PERMISSION_RP: u16 = PERMISSION_MAKE | PERMISSION_ASSERT;
const SCOPE_FIELDS: u16 = bit(LABEL_PERMISSIONS) | bit(LABEL_RP_ID);

const fn bit(label: i8) -> u16 {
    1 << label
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Retries = 0x01,
    Agreement = 0x02,
    Set = 0x03,
    Change = 0x04,
    Token = 0x05,
    TokenPermissions = 0x09,
}
impl Command {
    pub fn decode(value: u64) -> Option<Self> {
        match value {
            0x01 => Some(Self::Retries),
            0x02 => Some(Self::Agreement),
            0x03 => Some(Self::Set),
            0x04 => Some(Self::Change),
            0x05 => Some(Self::Token),
            0x09 => Some(Self::TokenPermissions),
            _ => None,
        }
    }
    pub const fn required(self) -> u16 {
        let agreement = bit(LABEL_PROTOCOL) | bit(LABEL_AGREEMENT);
        match self {
            Self::Retries => 0x00,
            Self::Agreement => bit(LABEL_PROTOCOL),
            Self::Set => agreement | bit(LABEL_AUTH) | bit(LABEL_NEW_PIN),
            Self::Change => agreement | bit(LABEL_AUTH) | bit(LABEL_NEW_PIN) | bit(LABEL_PIN_HASH),
            Self::Token => agreement | bit(LABEL_PIN_HASH),
            Self::TokenPermissions => agreement | bit(LABEL_PIN_HASH) | bit(LABEL_PERMISSIONS),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingParameter,
    InvalidParameter,
    UnauthorizedPermission,
}

/// After structural/field validation, require all command fields before scope
/// checks. A legacy token carrying forbidden scope but missing agreement/hash
/// reports MissingParameter; complete requests with scope report InvalidParameter.
/// This admission is independent of parser ownership and has no state effects.
pub fn admit(command: Command, seen: u16, permissions: u16, rp_present: bool) -> Result<(), Error> {
    if seen & command.required() != command.required() {
        return Err(Error::MissingParameter);
    }
    if command == Command::Token && seen & SCOPE_FIELDS != 0x00 {
        return Err(Error::InvalidParameter);
    }
    if command == Command::TokenPermissions && permissions & PERMISSION_RP != 0x00 && !rp_present {
        return Err(Error::MissingParameter);
    }
    Ok(())
}

/// Products select available bits, unavailable defined bits, and treatment of
/// unknown bits. This does not issue authority or modify token state.
#[derive(Clone, Copy)]
pub struct PermissionPolicy {
    pub supported: u16,
    pub rejected: u64,
    pub maximum: Option<u64>,
    pub protocol_two_only: u16,
}
impl PermissionPolicy {
    pub fn validate(self, protocol: Protocol, requested: u64) -> Result<u16, Error> {
        if requested == 0 {
            return Err(Error::InvalidParameter);
        }
        if self.maximum.is_some_and(|maximum| requested > maximum)
            || requested & self.rejected != 0x00
            || protocol == Protocol::One && requested & u64::from(self.protocol_two_only) != 0x00
        {
            return Err(Error::UnauthorizedPermission);
        }
        Ok((requested & u64::from(self.supported)) as u16)
    }
}

#[derive(Clone, Copy)]
pub enum EncryptedField {
    Auth,
    NewPin,
    PinHash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthError {
    WrongLength,
    PinTooLong,
}
impl EncryptedField {
    pub const fn bytes(self, protocol: Protocol) -> usize {
        match self {
            Self::Auth => protocol.auth_bytes(),
            Self::NewPin => PADDED_PIN_BYTES + protocol.iv_bytes(),
            Self::PinHash => PIN_HASH_BYTES + protocol.iv_bytes(),
        }
    }
    pub fn validate(self, protocol: Protocol, length: usize) -> Result<(), LengthError> {
        let expected = self.bytes(protocol);
        if matches!(self, Self::NewPin) && length > expected {
            return Err(LengthError::PinTooLong);
        }
        if length != expected {
            return Err(LengthError::WrongLength);
        }
        Ok(())
    }
}
