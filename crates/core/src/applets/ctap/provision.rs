// SPDX-License-Identifier: Apache-2.0
//! Attestation material is provisioned by ADMIN, never synthesized at runtime.
#[cfg(feature = "admin")]
use crate::{
    ports::{KeyOperation, Platform, Record, alg},
    runtime::workspace::Workspace,
};
#[cfg(feature = "admin")]
use canokey_ports::{Crypto as _, Memory as _, Storage as _};
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
    p: &mut Platform<'_, impl crate::ports::Backends>,
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
        super::settings::save(&super::settings::Sm2::DEFAULT.encode(), p)
    })();
    w.clear(p.memory);
    result
}

#[cfg(feature = "admin")]
pub(crate) struct Certificate(canokey_ctap::provision::Certificate);
#[cfg(feature = "admin")]
fn stage_error(error: canokey_ctap::provision::StageError<crate::ports::StorageError>) -> Error {
    use canokey_ctap::provision::StageError;
    match error {
        StageError::Source(_) => Error::Storage,
        StageError::Length => Error::Length,
        StageError::NotActive => Error::NotActive,
    }
}
#[cfg(feature = "admin")]
impl Certificate {
    pub const fn new() -> Self {
        Self(canokey_ctap::provision::Certificate::new())
    }
    pub fn active(&self) -> bool {
        self.0.active()
    }
    pub fn begin(
        &mut self,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Error> {
        self.0
            .begin(&mut super::adapter::CertificateStage(p.storage))
            .map_err(stage_error)
    }
    pub fn append(
        &mut self,
        used: &mut usize,
        bytes: &[u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Error> {
        self.0
            .append(
                used,
                bytes,
                CERT_LIMIT,
                &mut super::adapter::CertificateStage(p.storage),
            )
            .map_err(stage_error)
    }
    pub fn commit(
        &mut self,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Error> {
        self.0
            .commit(&mut super::adapter::CertificateStage(p.storage))
            .map_err(stage_error)
    }
    pub fn abort(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        self.0
            .abort(&mut super::adapter::CertificateStage(p.storage));
    }
}
