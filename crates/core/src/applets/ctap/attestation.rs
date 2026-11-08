// SPDX-License-Identifier: Apache-2.0
//! Shared record checks; callers retain their self-attestation and error policy.
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
