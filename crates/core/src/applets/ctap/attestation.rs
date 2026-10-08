// SPDX-License-Identifier: Apache-2.0
//! Shared record checks; callers retain their self-attestation and error policy.
use super::{Status, provision};
use crate::ports::{Platform, Record, StorageError};
use canokey_ports::Storage as _;

#[inline(never)]
pub(super) fn key(
    out: &mut [u8; 32],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), StorageError> {
    match p.storage.load(Record::CtapAttestationKey, out) {
        Ok(32) => Ok(()),
        Ok(_) => Err(StorageError::Unavailable),
        Err(error) => Err(error),
    }
}

#[inline(never)]
pub(super) fn certificate(
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<usize, Status> {
    let length = p
        .storage
        .size(Record::CtapCertificate)
        .map_err(|_| Status::Other)? as usize;
    if length == 0 || length > provision::CERT_LIMIT {
        Err(Status::Other)
    } else {
        Ok(length)
    }
}
