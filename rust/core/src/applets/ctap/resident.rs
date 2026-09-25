// SPDX-License-Identifier: Apache-2.0
//! Each discoverable credential is one compact atomic record. Enumeration scans
//! records, avoiding duplicate indexes, tombstones and cross-file recovery state.
use super::{
    Status,
    credential::{ID_BYTES, Id},
    credential_request::Parameters,
    crypto::equal,
};
use crate::ports::{Platform, Record, StorageError};

pub(super) const RESIDENT: u8 = 4;
pub(super) const LARGE_BLOB_KEY: u8 = 8;
pub(super) const MAX_BYTES: usize = ID_BYTES + 32 + 5 + 32 + 64 * 3 + 32;
pub(super) struct Entry<'a> {
    pub id: &'a Id,
    pub rp_hash: &'a [u8; 32],
    pub rp: &'a [u8],
    pub user: &'a [u8],
    pub name: &'a [u8],
    pub display: &'a [u8],
    pub blob: &'a [u8],
}
impl<'a> Entry<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() < ID_BYTES + 32 {
            return Err(Status::Other);
        }
        let id: &Id = bytes[..ID_BYTES].try_into().unwrap();
        let rp_hash = bytes[ID_BYTES..ID_BYTES + 32].try_into().unwrap();
        let mut rest = &bytes[ID_BYTES + 32..];
        let rp = take(&mut rest, 32)?;
        let user = take(&mut rest, 64)?;
        let name = take(&mut rest, 64)?;
        let display = take(&mut rest, 64)?;
        let blob = take(&mut rest, 32)?;
        if user.is_empty() || !rest.is_empty() || id[1] & RESIDENT == 0 {
            return Err(Status::Other);
        }
        for text in [rp, name, display] {
            core::str::from_utf8(text).map_err(|_| Status::Other)?;
        }
        let entry = Self {
            id,
            rp_hash,
            rp,
            user,
            name,
            display,
            blob,
        };
        if entry.rp.is_empty() {
            return Err(Status::Other);
        }
        Ok(entry)
    }
}
fn take<'a>(rest: &mut &'a [u8], limit: usize) -> Result<&'a [u8], Status> {
    let n = usize::from(*rest.first().ok_or(Status::Other)?);
    if n > limit || rest.len() < 1 + n {
        return Err(Status::Other);
    }
    let value = &rest[1..1 + n];
    *rest = &rest[1 + n..];
    Ok(value)
}
pub(super) fn text_prefix(bytes: &[u8]) -> &[u8] {
    match core::str::from_utf8(bytes) {
        Ok(_) => bytes,
        Err(error) => &bytes[..error.valid_up_to()],
    }
}
pub(super) fn load(
    index: u8,
    out: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<usize>, Status> {
    let record = Record::ctap_credential(index).ok_or(Status::Other)?;
    match p.storage.load(record, &mut out[..MAX_BYTES]) {
        Ok(n) => Ok(Some(n)),
        Err(StorageError::Missing) => Ok(None),
        Err(_) => Err(Status::Other),
    }
}
pub(super) fn store(
    params: &Parameters,
    id: &Id,
    rp_hash: &[u8; 32],
    out: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    let mut slot = None;
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some(n) = load(index, out, p)? {
            let entry = Entry::decode(&out[..n])?;
            if equal(entry.rp_hash, rp_hash) && equal(entry.user, &params.user[..params.user_len]) {
                slot = Some(index);
                break;
            }
        } else {
            slot.get_or_insert(index);
        }
    }
    let record = Record::ctap_credential(slot.ok_or(Status::KeyStoreFull)?).unwrap();
    out[..ID_BYTES].copy_from_slice(id);
    out[ID_BYTES..ID_BYTES + 32].copy_from_slice(rp_hash);
    let mut at = ID_BYTES + 32;
    for field in [
        text_prefix(&params.rp[..params.rp_len.min(32)]),
        &params.user[..params.user_len],
        &params.name[..params.name_len],
        &params.display[..params.display_len],
        &params.cred_blob[..params
            .cred_blob_len
            .filter(|&n| n <= params.cred_blob.len())
            .unwrap_or(0)],
    ] {
        out[at] = field.len() as u8;
        at += 1;
        out[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    p.storage
        .replace(record, &out[..at])
        .map_err(|_| Status::Other)
}

pub(super) fn find(
    id: &Id,
    rp_hash: &[u8; 32],
    out: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<(u8, usize)>, Status> {
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some(n) = load(index, out, p)? {
            let entry = Entry::decode(&out[..n])?;
            if equal(entry.id, id) && equal(entry.rp_hash, rp_hash) {
                return Ok(Some((index, n)));
            }
        }
    }
    Ok(None)
}

/// Small getNextAssertion cursor, not another request or key workspace.
pub(super) struct Assertion {
    pub rp: [u8; 32],
    pub client_hash: [u8; 32],
    pub next: u8,
    pub remaining: u8,
    pub uv: bool,
    pub up: bool,
    pub get_cred_blob: bool,
    pub third_party_payment: bool,
    pub hmac: super::hmac_secret::Prepared,
    pub started: u32,
}
impl Assertion {
    pub const fn new() -> Self {
        Self {
            rp: [0; 32],
            client_hash: [0; 32],
            next: 0,
            remaining: 0,
            uv: false,
            up: false,
            get_cred_blob: false,
            third_party_payment: false,
            hmac: super::hmac_secret::Prepared::new(),
            started: 0,
        }
    }
}
