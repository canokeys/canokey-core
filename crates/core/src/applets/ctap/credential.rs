// SPDX-License-Identifier: Apache-2.0
//! Compact authenticated key handles; non-resident credentials use no FS slots.
use super::{
    Status,
    crypto::{equal, mac},
};
use crate::ports::{KeyMaterial, Platform, Record, StorageError, alg};
use canokey_ports::{Crypto as _, Memory as _, Storage as _};

use canokey_ctap::credential::{self as shared, ExtensionDomain, HandleDomain, Scheme};
pub(super) use canokey_ctap::credential::{CRED_PROTECT_MASK, ID_BYTES, Id, THIRD_PARTY_PAYMENT};

// The native primitive accepts contiguous input. Lend the original bounded
// transcript buffer; no root/key or transcript borrow survives a MAC call.
struct CredentialMac<'a, 'p, B: crate::ports::Backends> {
    message: &'a mut [u8],
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> shared::Mac for CredentialMac<'_, '_, B> {
    type Error = Status;
    fn hmac_sha256(
        &mut self,
        root: &[u8; shared::KEY_BYTES],
        transcript: &shared::Transcript<'_>,
        out: &mut [u8; shared::KEY_BYTES],
    ) -> Result<(), Status> {
        let length = transcript.copy_to(self.message).ok_or(Status::Other)?;
        mac(root, &self.message[..length], out, self.platform)
    }
}

fn master(
    create: bool,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<[u8; 32], Status> {
    let mut key = [0; 32];
    let result = match p.storage.load(Record::CtapMaster, &mut key) {
        Ok(32) => Ok(()),
        Err(StorageError::Missing) if create => p
            .crypto
            .random(&mut key)
            .map_err(|_| Status::Other)
            .and_then(|()| {
                p.storage
                    .replace(Record::CtapMaster, &key)
                    .map_err(|_| Status::Other)
            }),
        Err(StorageError::Missing) => Err(Status::NoCredentials),
        _ => Err(Status::Other),
    };
    if let Err(error) = result {
        p.memory.wipe(&mut key);
        return Err(error);
    }
    Ok(key)
}

fn native_algorithm(scheme: Scheme) -> u8 {
    match scheme {
        Scheme::P256 => alg::P256,
        Scheme::Ed25519 => alg::ED25519,
        Scheme::Sm2 => alg::SM2,
        Scheme::MlDsa65 => alg::MLDSA65,
        Scheme::MlDsa44 => alg::MLDSA44,
    }
}
pub(super) fn algorithm(id: &Id) -> Result<u8, Status> {
    Scheme::decode(id[shared::ALGORITHM_OFFSET])
        .map(native_algorithm)
        .ok_or(Status::NoCredentials)
}

fn derive(
    id: &Id,
    rp: &[u8; 32],
    master: &[u8; 32],
    sm2: super::settings::Sm2,
    domain: HandleDomain,
    out: &mut [u8; shared::KEY_BYTES],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    let mut message = [0x00; shared::HANDLE_TRANSCRIPT_MAX_BYTES];
    let settings = sm2.encode();
    let settings = (id[shared::ALGORITHM_OFFSET] == Scheme::Sm2 as u8).then_some(&settings);
    shared::derive_handle(
        master,
        id,
        rp,
        domain,
        settings,
        out,
        &mut CredentialMac {
            message: &mut message,
            platform: p,
        },
    )
}

pub(super) fn create(
    algorithm: u8,
    flags: u8,
    sm2: super::settings::Sm2,
    rp: &[u8; 32],
    key: &mut KeyMaterial,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Id, Status> {
    let mut master = master(true, p)?;
    let result = (|| {
        let scheme = match algorithm {
            alg::P256 => Scheme::P256,
            alg::ED25519 => Scheme::Ed25519,
            alg::SM2 => Scheme::Sm2,
            alg::MLDSA65 => Scheme::MlDsa65,
            alg::MLDSA44 => Scheme::MlDsa44,
            _ => return Err(Status::UnsupportedAlgorithm),
        };
        shared::create(
            scheme,
            flags,
            &mut CreateCredential {
                master: &master,
                rp,
                sm2,
                scheme,
                key,
                platform: p,
            },
        )
    })();
    p.memory.wipe(&mut master);
    result
}

struct CreateCredential<'a, 'p, B: crate::ports::Backends> {
    master: &'a [u8; shared::KEY_BYTES],
    rp: &'a [u8; shared::RP_HASH_BYTES],
    sm2: super::settings::Sm2,
    scheme: Scheme,
    key: &'a mut KeyMaterial,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> shared::Creation for CreateCredential<'_, '_, B> {
    type Error = Status;
    type Credential = Id;
    fn random_nonce(&mut self, nonce: &mut [u8]) -> Result<(), Status> {
        self.platform
            .crypto
            .random(nonce)
            .map_err(|_| Status::Other)
    }
    fn prepare(&mut self, id: &Id) -> Result<[u8; shared::KEY_BYTES], Status> {
        let mut tag = [0x00; shared::KEY_BYTES];
        let result = (|| {
            derive(
                id,
                self.rp,
                self.master,
                self.sm2,
                HandleDomain::Tag,
                &mut tag,
                self.platform,
            )?;
            derive(
                id,
                self.rp,
                self.master,
                self.sm2,
                HandleDomain::Seed,
                (&mut self.key.bytes[..shared::KEY_BYTES])
                    .try_into()
                    .unwrap(),
                self.platform,
            )
        })();
        if let Err(error) = result {
            self.platform.memory.wipe(&mut tag);
            return Err(error);
        }
        Ok(tag)
    }
    fn clear_tag(&mut self, tag: &mut [u8; shared::KEY_BYTES]) {
        self.platform.memory.wipe(tag);
    }
    fn accept(&mut self, id: &Id) -> Option<Id> {
        shared::valid_signing_seed(
            self.scheme,
            (&self.key.bytes[..shared::KEY_BYTES]).try_into().unwrap(),
        )
        .then_some(*id)
    }
}
struct OpenCredential<'a, 'p, B: crate::ports::Backends> {
    master: &'a [u8; shared::KEY_BYTES],
    rp: &'a [u8; shared::RP_HASH_BYTES],
    sm2: super::settings::Sm2,
    scheme: Scheme,
    key: &'a mut KeyMaterial,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> shared::Opening for OpenCredential<'_, '_, B> {
    type Error = Status;
    type Credential = u8;
    fn tag(&mut self, id: &Id) -> Result<[u8; shared::KEY_BYTES], Status> {
        let mut tag = [0x00; shared::KEY_BYTES];
        if let Err(error) = derive(
            id,
            self.rp,
            self.master,
            self.sm2,
            HandleDomain::Tag,
            &mut tag,
            self.platform,
        ) {
            self.platform.memory.wipe(&mut tag);
            return Err(error);
        }
        Ok(tag)
    }
    fn equal(&self, expected: &[u8], computed: &[u8]) -> bool {
        equal(expected, computed)
    }
    fn clear_tag(&mut self, tag: &mut [u8; shared::KEY_BYTES]) {
        self.platform.memory.wipe(tag);
    }
    fn reject(&mut self) {
        // The outer owner clears the complete key backing on every failure.
    }
    fn accept(&mut self, id: &Id) -> Result<Option<u8>, Status> {
        let seed: &mut [u8; shared::KEY_BYTES] = (&mut self.key.bytes[..shared::KEY_BYTES])
            .try_into()
            .unwrap();
        derive(
            id,
            self.rp,
            self.master,
            self.sm2,
            HandleDomain::Seed,
            seed,
            self.platform,
        )?;
        Ok(shared::valid_signing_seed(self.scheme, seed).then_some(native_algorithm(self.scheme)))
    }
}

pub(super) fn open(
    id: &Id,
    sm2: super::settings::Sm2,
    rp: &[u8; 32],
    key: &mut KeyMaterial,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<u8, Status> {
    let result = (|| {
        let scheme = Scheme::decode(id[shared::ALGORITHM_OFFSET]).ok_or(Status::NoCredentials)?;
        let mut master = master(false, p)?;
        let result = shared::open(
            id,
            &mut OpenCredential {
                master: &master,
                rp,
                sm2,
                scheme,
                key,
                platform: p,
            },
        );
        // This root loan spans tag verification and the accepted seed derivation.
        // Erase it before returning either the key or an error to the caller.
        p.memory.wipe(&mut master);
        result?.ok_or(Status::NoCredentials)
    })();
    if result.is_err() {
        p.memory.wipe(&mut key.bytes);
    }
    result
}

pub(super) fn counter(
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<[u8; 4], Status> {
    let mut bytes = [0; 4];
    match p.storage.load(Record::CtapCounter, &mut bytes) {
        Ok(4) | Err(StorageError::Missing) => (),
        _ => return Err(Status::Other),
    }
    let n = u32::from_be_bytes(bytes)
        .checked_add(1)
        .ok_or(Status::Other)?;
    bytes = n.to_be_bytes();
    // Persist before publishing a signature; interrupted calls may skip counts,
    // but can never publish the same count after a reboot.
    p.storage
        .replace(Record::CtapCounter, &bytes)
        .map_err(|_| Status::Other)?;
    Ok(bytes)
}

/// Extension domains are separate from handle tags (0) and signing keys (1).
/// Domain 2 is largeBlobKey; 3/4 are hmac-secret without/with UV.
pub(super) fn extension_key(
    domain: ExtensionDomain,
    id: &Id,
    rp: &[u8; 32],
    out: &mut [u8; 32],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    let mut master = master(false, p)?;
    let mut message = [0x00; shared::EXTENSION_TRANSCRIPT_BYTES];
    let result = shared::derive_extension(
        &master,
        id,
        rp,
        domain,
        out,
        &mut CredentialMac {
            message: &mut message,
            platform: p,
        },
    );
    p.memory.wipe(&mut master);
    result
}

pub(super) fn large_blob_key(
    id: &Id,
    rp: &[u8; 32],
    out: &mut [u8; 32],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    extension_key(ExtensionDomain::LargeBlobKey, id, rp, out, p)
}

// Keep credential decoding available to management even when authentication is restricted.
pub(super) fn permitted(algorithm: u8) -> bool {
    !cfg!(feature = "ctap-restrict-algorithms") || matches!(algorithm, alg::P256 | alg::ED25519)
}
pub(super) fn permitted_id(id: &Id) -> bool {
    !cfg!(feature = "ctap-restrict-algorithms") || algorithm(id).is_ok_and(permitted)
}

/// Classic packed self-attestation cannot name a streamed PQ signing algorithm.
#[inline(always)]
pub(super) fn classic_cose_algorithm(algorithm: u8, sm2: super::settings::Sm2) -> i32 {
    match algorithm {
        alg::ED25519 => super::wire::cose::EDDSA,
        alg::SM2 => sm2.algorithm,
        _ => super::wire::cose::ES256,
    }
}
pub(super) fn cose_algorithm(algorithm: u8, sm2: super::settings::Sm2) -> i32 {
    match algorithm {
        alg::MLDSA65 => super::wire::cose::MLDSA65,
        alg::MLDSA44 => super::wire::cose::MLDSA44,
        _ => classic_cose_algorithm(algorithm, sm2),
    }
}
// Native classic public output is compressed Ed25519 (32 bytes), or the two
// 32-byte affine coordinates of P-256/SM2 without a SEC1 point prefix.
const ED25519_PUBLIC_BYTES: usize = 32;
const EC2_PUBLIC_BYTES: usize = 64;
/// AuthData construction dispatches streamed public keys before this capability.
/// Keep their large lengths out of the contiguous public-output check.
#[inline(always)]
pub(super) fn classic_public_length(algorithm: u8) -> usize {
    if algorithm == alg::ED25519 {
        ED25519_PUBLIC_BYTES
    } else {
        EC2_PUBLIC_BYTES
    }
}
pub(super) fn public_length(algorithm: u8) -> usize {
    if algorithm == alg::ED25519 {
        ED25519_PUBLIC_BYTES
    } else if let Some(params) = crate::ports::mldsa::parameters(algorithm) {
        params.public_bytes
    } else {
        EC2_PUBLIC_BYTES
    }
}

#[cfg(test)]
mod tests;
