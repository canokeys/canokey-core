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

/// Ordinary packed-attestation fallback and material-read ordering. Strict PQ
/// registration continues to require a certificate and key without fallback.
#[derive(Clone, Copy)]
pub enum Selection {
    /// Read certificate metadata and key even if the first read fails. Missing
    /// either permits self attestation; other IO and malformed keys are fatal.
    MissingEither,
    /// An admitted zero-length certificate skips key access. Missing/corrupt
    /// product records are classified by the source before entering selection.
    OptionalCertificate,
}

/// Product capabilities classify missing records and malformed material using
/// their existing error mapping. Key reads admit exactly PRIVATE_KEY_BYTES.
pub trait SelectionSource {
    type Error;
    fn certificate_length(&mut self) -> Result<usize, Self::Error>;
    fn key(&mut self, output: &mut [u8; PRIVATE_KEY_BYTES]) -> Result<(), Self::Error>;
    fn missing(error: &Self::Error) -> bool;
    fn invalid() -> Self::Error;
}

/// Select provisioned material into the caller's existing temporary key loan.
/// A zero certificate length means self attestation. Partial/failed key reads remain in `output`;
/// the caller must erase it on every exit, before any response publication.
#[inline(always)]
pub fn select<S: SelectionSource>(
    source: &mut S,
    output: &mut [u8; PRIVATE_KEY_BYTES],
    maximum: usize,
    selection: Selection,
) -> Result<usize, S::Error> {
    let certificate = source.certificate_length();
    match selection {
        Selection::MissingEither => {
            let key = source.key(output);
            match (key, certificate) {
                (Ok(()), Ok(length)) if length != 0 && length <= maximum => Ok(length),
                (Ok(()), Err(error)) if S::missing(&error) => Ok(0),
                (Err(error), Ok(_)) if S::missing(&error) => Ok(0),
                (Err(key), Err(certificate)) if S::missing(&key) && S::missing(&certificate) => {
                    Ok(0)
                }
                _ => Err(S::invalid()),
            }
        }
        Selection::OptionalCertificate => {
            let length = certificate?;
            if length > maximum {
                return Err(S::invalid());
            }
            if length == 0 {
                return Ok(0);
            }
            source.key(output)?;
            Ok(length)
        }
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
