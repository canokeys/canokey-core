// SPDX-License-Identifier: Apache-2.0
//! Compact authenticated key handles; non-resident credentials use no FS slots.
use super::{
    Status,
    crypto::{equal, mac},
};
use crate::{
    ports::{Platform, Record, StorageError, alg},
    runtime::workspace::Workspace,
};

// Algorithm, policy flags, random nonce, truncated HMAC. The RP hash is bound
// cryptographically rather than repeated in every credential ID.
pub(super) const THIRD_PARTY_PAYMENT: u8 = 16;
pub(super) const ID_BYTES: usize = 34;
pub(super) type Id = [u8; ID_BYTES];
const TAG: usize = 18;

fn master(create: bool, p: &mut Platform<'_>) -> Result<[u8; 32], Status> {
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
    match id[0] {
        0 => Ok(alg::P256),
        1 => Ok(alg::ED25519),
        2 => Ok(alg::SM2),
        3 => Ok(alg::MLDSA65),
        _ => Err(Status::NoCredentials),
    }
}

fn derive(
    id: &Id,
    rp: &[u8; 32],
    master: &[u8; 32],
    sm2: super::settings::Sm2,
    w: &mut Workspace,
    p: &mut Platform<'_>,
) -> Result<[u8; 32], Status> {
    let mut message = [0; 1 + TAG + 32 + 8];
    message[1..1 + TAG].copy_from_slice(&id[..TAG]);
    message[1 + TAG..1 + TAG + 32].copy_from_slice(rp);
    let length = if id[0] == 2 {
        message[1 + TAG + 32..].copy_from_slice(&sm2.encode());
        message.len()
    } else {
        1 + TAG + 32
    };
    let mut tag = [0; 32];
    mac(master, &message[..length], &mut tag, p)?;
    message[0] = 1; // Domain separation: public authenticator tag vs private key.
    if let Err(error) = mac(
        master,
        &message[..length],
        (&mut w.key.bytes[..32]).try_into().unwrap(),
        p,
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
    w: &mut Workspace,
    p: &mut Platform<'_>,
) -> Result<Id, Status> {
    let mut master = master(true, p)?;
    let result = (|| {
        let mut id = [0; ID_BYTES];
        id[0] = match algorithm {
            alg::P256 => 0,
            alg::ED25519 => 1,
            alg::SM2 => 2,
            alg::MLDSA65 => 3,
            _ => return Err(Status::UnsupportedAlgorithm),
        };
        id[1] = flags;
        // HMAC output is not necessarily a valid P-256/SM2 scalar. Retry with
        // a fresh nonce, without biased modular reduction.
        loop {
            p.crypto
                .random(&mut id[2..TAG])
                .map_err(|_| Status::Other)?;
            let mut tag = derive(&id, rp, &master, sm2, w, p)?;
            id[TAG..].copy_from_slice(&tag[..16]);
            p.memory.wipe(&mut tag);
            if matches!(algorithm, alg::P256 | alg::SM2)
                && !valid_scalar(algorithm, &w.key.bytes[..32])
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
    w: &mut Workspace,
    p: &mut Platform<'_>,
) -> Result<u8, Status> {
    let algorithm = algorithm(id)?;
    let mut master = master(false, p)?;
    let result = derive(id, rp, &master, sm2, w, p);
    p.memory.wipe(&mut master);
    let mut tag = result?;
    let valid = equal(&id[TAG..], &tag[..16]);
    p.memory.wipe(&mut tag);
    if !valid {
        p.memory.wipe(&mut w.key.bytes);
        return Err(Status::NoCredentials);
    }
    Ok(algorithm)
}

pub(super) fn counter(p: &mut Platform<'_>) -> Result<[u8; 4], Status> {
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
    domain: u8,
    id: &Id,
    rp: &[u8; 32],
    out: &mut [u8; 32],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    let mut master = master(false, p)?;
    let mut message = [0; 1 + ID_BYTES + 32];
    message[0] = domain;
    message[1..1 + ID_BYTES].copy_from_slice(id);
    message[1 + ID_BYTES..].copy_from_slice(rp);
    let result = mac(&master, &message, out, p);
    p.memory.wipe(&mut master);
    result
}

pub(super) fn large_blob_key(
    id: &Id,
    rp: &[u8; 32],
    out: &mut [u8; 32],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    extension_key(2, id, rp, out, p)
}

pub(super) fn cose_algorithm(algorithm: u8, sm2: super::settings::Sm2) -> i32 {
    match algorithm {
        alg::P256 => -7,
        alg::ED25519 => -8,
        alg::MLDSA65 => -49,
        alg::SM2 => sm2.algorithm,
        _ => -7,
    }
}
pub(super) fn public_length(algorithm: u8) -> usize {
    if algorithm == alg::ED25519 {
        32
    } else if algorithm == alg::MLDSA65 {
        super::pq::PUBLIC_BYTES
    } else {
        64
    }
}
