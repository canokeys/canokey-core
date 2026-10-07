// SPDX-License-Identifier: Apache-2.0
//! Attestation material is provisioned by ADMIN, never synthesized at runtime.
#[cfg(feature = "admin")]
use crate::{
    ports::{KeyOperation, Platform, Record, alg},
    runtime::workspace::Workspace,
};
#[cfg(feature = "admin")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Length,
    Invalid,
    Storage,
    NotActive,
}

pub(crate) const CERT_LIMIT: usize = 1152;
pub(super) const AAGUID: [u8; 16] = [
    0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49, 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4,
];
#[cfg(feature = "admin")]
pub(crate) fn install_key(
    key: &mut [u8; 32],
    w: &mut Workspace,
    p: &mut Platform<'_>,
) -> Result<(), Error> {
    w.clear(p.memory);
    w.key.bytes[..32].copy_from_slice(key);
    p.memory.wipe(key);
    let result = (|| {
        p.crypto
            .key_operation(KeyOperation::Validate, alg::P256, &mut w.key, &[], w.output)
            .map_err(|_| Error::Invalid)?;
        p.storage
            .replace(Record::CtapAttestationKey, &w.key.bytes[..32])
            .map_err(|_| Error::Storage)?;
        super::settings::Sm2::save(&super::settings::Sm2::DEFAULT.encode(), p)
    })();
    w.clear(p.memory);
    result
}

#[cfg(feature = "admin")]
pub(crate) struct Certificate {
    active: bool,
}
#[cfg(feature = "admin")]
impl Certificate {
    pub const fn new() -> Self {
        Self { active: false }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn begin(&mut self, p: &mut Platform<'_>) -> Result<(), Error> {
        p.storage.stage_begin().map_err(|_| Error::Storage)?;
        self.active = true;
        Ok(())
    }
    pub fn append(
        &mut self,
        used: &mut usize,
        bytes: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        *used = used
            .checked_add(bytes.len())
            .filter(|n| *n <= CERT_LIMIT)
            .ok_or(Error::Length)?;
        p.storage.stage_append(bytes).map_err(|_| Error::Storage)
    }
    pub fn commit(&mut self, p: &mut Platform<'_>) -> Result<(), Error> {
        if !self.active {
            return Err(Error::NotActive);
        }
        p.storage
            .stage_commit(Record::CtapCertificate)
            .map_err(|_| Error::Storage)?;
        self.active = false;
        Ok(())
    }
    pub fn abort(&mut self, p: &mut Platform<'_>) {
        if self.active {
            p.storage.stage_abort();
            self.active = false;
        }
    }
}
