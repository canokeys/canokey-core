// SPDX-License-Identifier: Apache-2.0
//! Provisioned COSE identifiers survive credential reset. The record is two BE32s.
use super::Status;
use crate::ports::{Platform, Record, StorageError};
#[cfg(feature = "admin")]
use canokey_protocol::response::StatusWord as Sw;

#[derive(Clone, Copy)]
pub(crate) struct Sm2 {
    pub curve: i32,
    pub algorithm: i32,
}
impl Sm2 {
    pub const DEFAULT: Self = Self {
        curve: 9,
        algorithm: -54,
    };
    pub fn encode(self) -> [u8; 8] {
        let mut wire = [0; 8];
        wire[..4].copy_from_slice(&self.curve.to_be_bytes());
        wire[4..].copy_from_slice(&self.algorithm.to_be_bytes());
        wire
    }
    pub(super) fn decode(wire: &[u8]) -> Option<Self> {
        if wire.len() != 8 {
            return None;
        }
        let value = Self {
            curve: i32::from_be_bytes(wire[..4].try_into().ok()?),
            algorithm: i32::from_be_bytes(wire[4..].try_into().ok()?),
        };
        // Same reserved COSE identifiers as the C profile.
        if matches!(value.curve, 0..=8 | 256..=259) || matches!(value.algorithm, -7 | -8 | -49) {
            return None;
        }
        Some(value)
    }
    pub fn load(p: &mut Platform<'_>) -> Result<Self, Status> {
        let mut wire = [0; 8];
        match p.storage.load(Record::CtapSm2, &mut wire) {
            Err(StorageError::Missing) => Ok(Self::DEFAULT),
            Ok(8) => Self::decode(&wire).ok_or(Status::Other),
            _ => Err(Status::Other),
        }
    }
    #[cfg(feature = "admin")]
    pub fn save(wire: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        if wire.len() != 8 {
            return Err(Sw::WRONG_LENGTH);
        }
        Self::decode(wire).ok_or(Sw::WRONG_DATA)?;
        p.storage
            .replace(Record::CtapSm2, wire)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)
    }
}
