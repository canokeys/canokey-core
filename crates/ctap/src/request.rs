// SPDX-License-Identifier: Apache-2.0
//! Common parameterless command admission for streamed and borrowed requests.
use crate::{config::Command, status::Status};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parameterless {
    GetInfo,
    Reset,
    GetNextAssertion,
    Selection,
}
/// Missing command or extra bytes on a parameterless command fail with the
/// standard length status. Other commands retain their own schema/error policy.
/// The caller supplies only metadata; no input or response backing is retained.
pub fn parameterless(
    command: Option<u8>,
    has_parameters: bool,
) -> Result<Option<Parameterless>, Status> {
    let command = command.ok_or(Status::InvalidLength)?;
    let parsed = match command {
        value if value == Command::GetInfo as u8 => Parameterless::GetInfo,
        value if value == Command::Reset as u8 => Parameterless::Reset,
        value if value == Command::GetNextAssertion as u8 => Parameterless::GetNextAssertion,
        value if value == Command::Selection as u8 => Parameterless::Selection,
        _ => return Ok(None),
    };
    if has_parameters {
        return Err(Status::InvalidLength);
    }
    Ok(Some(parsed))
}

pub mod agreement;
pub mod borrowed;
pub mod credential;
pub mod hmac_secret;
pub mod stream;

/// Parsing reports product errors directly, preserving first-error identity
/// without converting a full owned request or retaining an application borrow.
pub trait Error: Copy {
    const INVALID_CBOR: Self;
    const UNEXPECTED_TYPE: Self;
    const INVALID_LENGTH: Self;
    const INVALID_PARAMETER: Self;
    const MISSING_PARAMETER: Self;
    const LIMIT_EXCEEDED: Self;
    const UNSUPPORTED_ALGORITHM: Self;
    const PIN_AUTH_INVALID: Self;
    const UNSUPPORTED_OPTION: Self;
    const INVALID_OPTION: Self;
    const INTERNAL: Self;
}
impl Error for Status {
    const INVALID_CBOR: Self = Self::InvalidCbor;
    const UNEXPECTED_TYPE: Self = Self::CborUnexpectedType;
    const INVALID_LENGTH: Self = Self::InvalidLength;
    const INVALID_PARAMETER: Self = Self::InvalidParameter;
    const MISSING_PARAMETER: Self = Self::MissingParameter;
    const LIMIT_EXCEEDED: Self = Self::LimitExceeded;
    const UNSUPPORTED_ALGORITHM: Self = Self::UnsupportedAlgorithm;
    const PIN_AUTH_INVALID: Self = Self::PinAuthInvalid;
    const UNSUPPORTED_OPTION: Self = Self::UnsupportedOption;
    const INVALID_OPTION: Self = Self::InvalidOption;
    const INTERNAL: Self = Self::Internal;
}
