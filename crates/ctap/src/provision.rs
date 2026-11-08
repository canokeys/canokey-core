// SPDX-License-Identifier: Apache-2.0
//! Attestation material admission and explicit certificate staging; no authority or key generation.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError<E> {
    Source(E),
    Length,
    NotActive,
}

/// Owns only the publication latch. The product owns its byte count, authorized
/// command and staging backend; no handle, fragment or capability is retained.
/// The owner must abort on cancellation/error/reset. Drop cannot do so because
/// it owns no backend borrow. Failed commit stays active until the owner aborts.
pub struct Certificate {
    active: bool,
}
impl Default for Certificate {
    fn default() -> Self {
        Self::new()
    }
}
impl Certificate {
    pub const fn new() -> Self {
        Self { active: false }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn begin<S: crate::ports::CertificateStage>(
        &mut self,
        stage: &mut S,
    ) -> Result<(), StageError<S::Error>> {
        stage.begin().map_err(StageError::Source)?;
        self.active = true;
        Ok(())
    }
    pub fn append<S: crate::ports::CertificateStage>(
        &mut self,
        used: &mut usize,
        bytes: &[u8],
        maximum: usize,
        stage: &mut S,
    ) -> Result<(), StageError<S::Error>> {
        // Advance admission before IO, preserving the product's command byte
        // count even on backend failure. Only commit publishes staged bytes.
        *used = used
            .checked_add(bytes.len())
            .filter(|n| *n <= maximum)
            .ok_or(StageError::Length)?;
        stage.append(bytes).map_err(StageError::Source)
    }
    pub fn commit<S: crate::ports::CertificateStage>(
        &mut self,
        stage: &mut S,
    ) -> Result<(), StageError<S::Error>> {
        if !self.active {
            return Err(StageError::NotActive);
        }
        stage.commit().map_err(StageError::Source)?;
        self.active = false;
        Ok(())
    }
    pub fn abort<S: crate::ports::CertificateStage>(&mut self, stage: &mut S) {
        if self.active {
            stage.abort();
            self.active = false;
        }
    }
}
