// SPDX-License-Identifier: Apache-2.0
//! Read admission for product-provisioned attestation; no key generation or writes.
use crate::ports::Attestation;

pub const PRIVATE_KEY_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError<E> {
    Source(E),
    Length,
}

#[derive(Clone, Copy)]
pub enum CertificatePolicy {
    Required,
    Optional,
}

/// The output remains caller-owned, including on short or failed reads. The
/// caller must wipe partially supplied key bytes on every failure/close path.
pub fn key<S: Attestation>(
    source: &mut S,
    out: &mut [u8; PRIVATE_KEY_BYTES],
) -> Result<(), ReadError<S::Error>> {
    match source.key(out).map_err(ReadError::Source)? {
        PRIVATE_KEY_BYTES => Ok(()),
        _ => Err(ReadError::Length),
    }
}

/// Required certificates reject zero; optional zero means unprovisioned. Each
/// product supplies its existing storage limit and retains fallback/error policy.
pub fn certificate_length<S: Attestation>(
    source: &mut S,
    maximum: usize,
    policy: CertificatePolicy,
) -> Result<usize, ReadError<S::Error>> {
    let length = source.certificate_length().map_err(ReadError::Source)?;
    if length > maximum || (length == 0 && matches!(policy, CertificatePolicy::Required)) {
        Err(ReadError::Length)
    } else {
        Ok(length)
    }
}
