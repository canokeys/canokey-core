// SPDX-License-Identifier: Apache-2.0
//! Standard ClientPIN response bodies; products own status and publication.
use super::{KEY_BYTES, Protocol, agreement, cipher};

pub const LABEL_AGREEMENT: u8 = 0x01;
pub const LABEL_TOKEN: u8 = 0x02;
pub const LABEL_RETRIES: u8 = 0x03;
pub const LABEL_POWER_CYCLE: u8 = 0x04;
pub const TOKEN_PREFIX_BYTES: usize = 4;
pub const TOKEN_ENCODED_MAX_BYTES: usize = KEY_BYTES + cipher::BLOCK_BYTES;
pub const KEY_AGREEMENT_BYTES: usize = 2 + agreement::ENCODED_KEY_BYTES;

/// One-entry map: keyAgreement(1), followed by its five-field COSE_Key.
#[inline]
pub fn key_agreement<E>(
    point: &[u8; agreement::POINT_BYTES],
    mut emit: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    emit(&[0xa1, LABEL_AGREEMENT])?;
    agreement::encode(point, emit)
}

/// Core reports retries alone; products exposing powerCycleState add key 4.
/// Counts are canonical unsigned u8 values, including diagnostic values > 23.
#[inline]
pub fn retries<E>(
    remaining: u8,
    power_cycle: Option<bool>,
    mut emit: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    emit(&[
        if power_cycle.is_some() { 0xa2 } else { 0xa1 },
        LABEL_RETRIES,
    ])?;
    if remaining < 24 {
        emit(&[remaining])?;
    } else {
        emit(&[0x18, remaining])?;
    }
    if let Some(blocked) = power_cycle {
        emit(&[LABEL_POWER_CYCLE, if blocked { 0xf5 } else { 0xf4 }])?;
    }
    Ok(())
}

/// CTAP 2.1 response map(1), pinUvAuthToken(2), bstr header 58 then byte length.
/// The owner can encrypt directly after this prefix and install it only after
/// encryption succeeds; the CTAP status byte belongs to the outer response.
pub const fn token_prefix(protocol: Protocol) -> [u8; TOKEN_PREFIX_BYTES] {
    [
        0xa1,
        LABEL_TOKEN,
        0x58,
        (KEY_BYTES + protocol.iv_bytes()) as u8,
    ]
}
#[inline]
pub fn token<E>(
    protocol: Protocol,
    encoded: &[u8; TOKEN_ENCODED_MAX_BYTES],
    mut emit: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    emit(&token_prefix(protocol))?;
    emit(&encoded[..KEY_BYTES + protocol.iv_bytes()])
}
