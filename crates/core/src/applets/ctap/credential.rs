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
use shared::{NONCE_OFFSET, TAG_BYTES, TAG_OFFSET};

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

pub(super) fn algorithm(id: &Id) -> Result<u8, Status> {
    match Scheme::decode(id[shared::ALGORITHM_OFFSET]) {
        Some(Scheme::P256) => Ok(alg::P256),
        Some(Scheme::Ed25519) => Ok(alg::ED25519),
        Some(Scheme::Sm2) => Ok(alg::SM2),
        Some(Scheme::MlDsa65) => Ok(alg::MLDSA65),
        Some(Scheme::MlDsa44) => Ok(alg::MLDSA44),
        None => Err(Status::NoCredentials),
    }
}

fn derive(
    id: &Id,
    rp: &[u8; 32],
    master: &[u8; 32],
    sm2: super::settings::Sm2,
    key: &mut KeyMaterial,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<[u8; 32], Status> {
    let mut message = [0x00; shared::HANDLE_TRANSCRIPT_MAX_BYTES];
    let settings = sm2.encode();
    let settings = (id[shared::ALGORITHM_OFFSET] == Scheme::Sm2 as u8).then_some(&settings);
    let mut mac = CredentialMac {
        message: &mut message,
        platform: p,
    };
    let mut tag = [0x00; shared::KEY_BYTES];
    shared::derive_handle(
        master,
        id,
        rp,
        HandleDomain::Tag,
        settings,
        &mut tag,
        &mut mac,
    )?;
    if let Err(error) = shared::derive_handle(
        master,
        id,
        rp,
        HandleDomain::Seed,
        settings,
        (&mut key.bytes[..shared::KEY_BYTES]).try_into().unwrap(),
        &mut mac,
    ) {
        p.memory.wipe(&mut tag);
        return Err(error);
    }
    Ok(tag)
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
        let mut id = [0; ID_BYTES];
        id[shared::ALGORITHM_OFFSET] = match algorithm {
            alg::P256 => Scheme::P256 as u8,
            alg::ED25519 => Scheme::Ed25519 as u8,
            alg::SM2 => Scheme::Sm2 as u8,
            alg::MLDSA65 => Scheme::MlDsa65 as u8,
            alg::MLDSA44 => Scheme::MlDsa44 as u8,
            _ => return Err(Status::UnsupportedAlgorithm),
        };
        id[shared::POLICY_OFFSET] = flags;
        // HMAC output is not necessarily a valid P-256/SM2 scalar. Retry with
        // a fresh nonce, without biased modular reduction.
        loop {
            p.crypto
                .random(&mut id[NONCE_OFFSET..TAG_OFFSET])
                .map_err(|_| Status::Other)?;
            let mut tag = derive(&id, rp, &master, sm2, key, p)?;
            id[TAG_OFFSET..].copy_from_slice(&tag[..TAG_BYTES]);
            p.memory.wipe(&mut tag);
            if matches!(algorithm, alg::P256 | alg::SM2)
                && !valid_scalar(algorithm, &key.bytes[..32])
            {
                continue;
            }
            return Ok(id);
        }
    })();
    p.memory.wipe(&mut master);
    result
}

fn valid_scalar(algorithm: u8, scalar: &[u8]) -> bool {
    // SEC 2 secp256r1 group order n, big-endian; valid scalars satisfy 0 < d < n.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    // SM2 excludes n-1 as well: signing needs the inverse of 1+d.
    const SM2_LIMIT: [u8; 32] = [
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5,
        0x41, 0x22,
    ];
    let limit = if algorithm == alg::SM2 {
        &SM2_LIMIT
    } else {
        &ORDER
    };
    scalar.iter().any(|b| *b != 0) && scalar < limit.as_slice()
}

pub(super) fn open(
    id: &Id,
    sm2: super::settings::Sm2,
    rp: &[u8; 32],
    key: &mut KeyMaterial,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<u8, Status> {
    let algorithm = algorithm(id)?;
    let mut master = master(false, p)?;
    let result = derive(id, rp, &master, sm2, key, p);
    p.memory.wipe(&mut master);
    let mut tag = result?;
    let valid = equal(&id[TAG_OFFSET..], &tag[..TAG_BYTES]);
    p.memory.wipe(&mut tag);
    if !valid {
        p.memory.wipe(&mut key.bytes);
        return Err(Status::NoCredentials);
    }
    Ok(algorithm)
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

pub(super) fn cose_algorithm(algorithm: u8, sm2: super::settings::Sm2) -> i32 {
    match algorithm {
        alg::P256 => super::wire::cose::ES256,
        alg::ED25519 => super::wire::cose::EDDSA,
        alg::MLDSA65 => super::wire::cose::MLDSA65,
        alg::MLDSA44 => super::wire::cose::MLDSA44,
        alg::SM2 => sm2.algorithm,
        _ => super::wire::cose::ES256,
    }
}
pub(super) fn public_length(algorithm: u8) -> usize {
    if algorithm == alg::ED25519 {
        32
    } else if let Some(params) = crate::ports::mldsa::parameters(algorithm) {
        params.public_bytes
    } else {
        64
    }
}
