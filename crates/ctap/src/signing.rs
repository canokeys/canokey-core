// SPDX-License-Identifier: Apache-2.0
//! Ordinary CTAP signatures over authenticatorData || clientDataHash. The
//! synchronous caller owns transcript, key, output and failure cleanup. PQ
//! streaming and product proofs use separate engines, not these algorithms.

pub const DIGEST_BYTES: usize = 32;
pub const RAW_SIGNATURE_BYTES: usize = 64;
pub const MAX_ES256_SIGNATURE_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Es256,
    Ed25519,
    Sm2,
}

/// A signature can remain in an existing workspace or be an existing bounded
/// native return value. The engine never allocates transcript/signature backing.
pub trait Backend {
    type Error;
    type Signature;
    fn digest(
        &mut self,
        algorithm: Algorithm,
        output: &mut [u8; DIGEST_BYTES],
    ) -> Result<(), Self::Error>;
    fn sign(&mut self, digest: Option<&[u8; DIGEST_BYTES]>)
    -> Result<Self::Signature, Self::Error>;
    fn length(&self, signature: &Self::Signature) -> usize;
    fn der(&mut self, signature: Self::Signature) -> Result<usize, Self::Error>;
    fn raw(&mut self, signature: Self::Signature) -> Result<usize, Self::Error>;
    fn invalid_signature() -> Self::Error;
}

/// ES256 signs SHA-256; SM2 signs its ZA-prefixed digest and keeps fixed r || s;
/// Ed25519 signs the unmodified transcript. Only ES256 uses ASN.1 DER. Backend
/// errors stop before encoding; erasure and publication remain caller-owned.
#[inline(always)]
pub fn sign<B: Backend>(algorithm: Algorithm, mut backend: B) -> Result<usize, B::Error> {
    let mut digest = [0x00; DIGEST_BYTES];
    let prepared = match algorithm {
        Algorithm::Ed25519 => None,
        Algorithm::Es256 | Algorithm::Sm2 => {
            backend.digest(algorithm, &mut digest)?;
            Some(&digest)
        }
    };
    let signature = backend.sign(prepared)?;
    if backend.length(&signature) != RAW_SIGNATURE_BYTES {
        return Err(B::invalid_signature());
    }
    match algorithm {
        Algorithm::Es256 => backend.der(signature),
        Algorithm::Ed25519 | Algorithm::Sm2 => backend.raw(signature),
    }
}
