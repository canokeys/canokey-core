// SPDX-License-Identifier: Apache-2.0
//! Provisioned SM2 COSE identifiers; products retain authorization and recovery.
use crate::ports::Sm2Settings;
use canokey_ports::StorageError;

/// Persistent record: signed curve identifier, then signed algorithm identifier,
/// each a four-byte big-endian integer. This is the CanoKey provisioning ABI,
/// independent of the variable-length CBOR representation of COSE integers.
pub const RECORD_BYTES: usize = 8;
const IDENTIFIER_BYTES: usize = 4;
const ES256: i32 = -7;
const EDDSA: i32 = -8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sm2 {
    pub curve: i32,
    pub algorithm: i32,
}
impl Sm2 {
    pub const DEFAULT: Self = Self {
        curve: 9,
        algorithm: -54,
    };
    pub fn encode(self) -> [u8; RECORD_BYTES] {
        let mut wire = [0x00; RECORD_BYTES];
        wire[..IDENTIFIER_BYTES].copy_from_slice(&self.curve.to_be_bytes());
        wire[IDENTIFIER_BYTES..].copy_from_slice(&self.algorithm.to_be_bytes());
        wire
    }
    pub fn decode(wire: &[u8]) -> Option<Self> {
        if wire.len() != RECORD_BYTES {
            return None;
        }
        let value = Self {
            curve: i32::from_be_bytes(wire[..IDENTIFIER_BYTES].try_into().ok()?),
            algorithm: i32::from_be_bytes(wire[IDENTIFIER_BYTES..].try_into().ok()?),
        };
        // Keep configured SM2 identifiers disjoint from the supported standard
        // COSE curves and ES256/EdDSA/ML-DSA algorithm assignments.
        if matches!(value.curve, 0..=8 | 256..=259)
            || matches!(value.algorithm, ES256 | EDDSA)
            || canokey_ports::mldsa::from_cose(value.algorithm).is_some()
        {
            return None;
        }
        Some(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadError;

/// Missing configuration uses the provisioning default. I/O failures and
/// malformed/short records must not silently become an unconfigured device.
pub fn load(source: &mut impl Sm2Settings) -> Result<Sm2, ReadError> {
    let mut wire = [0x00; RECORD_BYTES];
    match source.load(&mut wire) {
        Err(StorageError::Missing) => Ok(Sm2::DEFAULT),
        Ok(RECORD_BYTES) => Sm2::decode(&wire).ok_or(ReadError),
        _ => Err(ReadError),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    Length,
    Invalid,
    Storage,
}

/// Validate before the first storage operation. The caller must already hold
/// provisioning authority; this capability cannot install a key or certificate.
pub fn save(wire: &[u8], target: &mut impl Sm2Settings) -> Result<(), WriteError> {
    if wire.len() != RECORD_BYTES {
        return Err(WriteError::Length);
    }
    Sm2::decode(wire).ok_or(WriteError::Invalid)?;
    target.replace(wire).map_err(|_| WriteError::Storage)
}
