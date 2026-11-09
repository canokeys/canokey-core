// SPDX-License-Identifier: Apache-2.0
//! Record adapters for shared material admission; callers own temporary-key erasure.
use super::{Status, provision};
use crate::ports::{Platform, StorageError};
use canokey_ctap::provision::{self as common, CertificatePolicy, ReadError};

#[inline(never)]
pub(super) fn key(
    out: &mut [u8; 32],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), StorageError> {
    common::key(&mut super::adapter::Attestation(p.storage), out).map_err(|error| match error {
        ReadError::Source(error) => error,
        ReadError::Length => StorageError::Unavailable,
    })
}

#[inline(never)]
pub(super) fn certificate(
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<usize, Status> {
    common::certificate_length(
        &mut super::adapter::Attestation(p.storage),
        provision::CERT_LIMIT,
        CertificatePolicy::Required,
    )
    .map_err(|_| Status::Other)
}

// Retain the outlined key-read frame while the shared selector owns read order
// and fallback. Its caller erases partially supplied temporary key bytes.
pub(super) struct Material<'a, 'p, B: crate::ports::Backends>(pub &'a mut Platform<'p, B>);
impl<B: crate::ports::Backends> common::SelectionSource for Material<'_, '_, B> {
    type Error = StorageError;
    #[inline(always)]
    fn key(&mut self, out: &mut [u8; common::PRIVATE_KEY_BYTES]) -> Result<(), StorageError> {
        key(out, self.0)
    }
    #[inline(always)]
    fn certificate_length(&mut self) -> Result<usize, StorageError> {
        canokey_ctap::ports::Attestation::certificate_length(&mut super::adapter::Attestation(
            self.0.storage,
        ))
    }
    #[inline(always)]
    fn missing(error: &StorageError) -> bool {
        matches!(error, StorageError::Missing)
    }
    #[inline(always)]
    fn invalid() -> StorageError {
        StorageError::Unavailable
    }
}
