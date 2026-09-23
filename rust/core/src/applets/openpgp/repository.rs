// SPDX-License-Identifier: Apache-2.0
//! Compact records; fixed field offsets are an in-memory view only.
use super::domain::Error;
use super::{domain::Algorithm, pin};
use crate::mechanisms::key_storage;
use crate::{
    Platform,
    ports::{Record, StorageError},
};
pub const STATE_LEN: usize = 512;
pub const META_LEN: usize = 31;
pub const KEYS: [Record; 3] = [Record::PgpSig, Record::PgpDec, Record::PgpAut];
pub const CERTS: [Record; 3] = [Record::PgpCertSig, Record::PgpCertDec, Record::PgpCertAut];
pub fn io(_: StorageError) -> Error {
    Error::Storage
}
// State: version, terminated, PW1 reuse, cache seconds, reserved[4];
// CA fingerprints[60]; length-prefixed name(39), login(63), lang(8), sex(1), URL(255).
pub fn field(tag: u16) -> Option<(usize, usize)> {
    match tag {
        0x5b => Some((68, 39)),
        0x5e => Some((108, 63)),
        0x5f2d => Some((172, 8)),
        0x5f35 => Some((181, 1)),
        0x5f50 => Some((183, 255)),
        _ => None,
    }
}
const FIELDS: [(usize, usize); 5] = [(68, 39), (108, 63), (172, 8), (181, 1), (183, 255)];
const STATE_HEADER: usize = 64; // Four flags followed by three CA fingerprints.
pub fn state(p: &mut Platform<'_>, b: &mut [u8; STATE_LEN]) -> Result<(), Error> {
    let n = p.storage.load(Record::PgpState, b).map_err(io)?;
    if n < STATE_HEADER || b[0] != 1 {
        return Err(Error::Storage);
    }
    let mut starts = [0; 5];
    let mut at = STATE_HEADER;
    for (i, (_, max)) in FIELDS.iter().enumerate() {
        if at >= n || b[at] as usize > *max || at + 1 + b[at] as usize > n {
            return Err(Error::Storage);
        }
        starts[i] = at;
        at += 1 + b[at] as usize;
    }
    if at != n {
        return Err(Error::Storage);
    }
    for (i, (off, max)) in FIELDS.iter().enumerate().rev() {
        let from = starts[i];
        let len = 1 + b[from] as usize;
        b.copy_within(from..from + len, *off);
        b[off + len..off + 1 + max].fill(0);
    }
    b.copy_within(4..STATE_HEADER, 8);
    b[4..8].fill(0);
    b[439..].fill(0);
    Ok(())
}
pub fn save_state(p: &mut Platform<'_>, b: &[u8; STATE_LEN]) -> Result<(), Error> {
    let result = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(&b[..4]).map_err(io)?;
        p.storage.stage_append(&b[8..68]).map_err(io)?;
        for (off, max) in FIELDS {
            let n = b[off] as usize;
            if n > max {
                return Err(Error::Storage);
            }
            p.storage.stage_append(&b[off..off + 1 + n]).map_err(io)?;
        }
        p.storage.stage_commit(Record::PgpState).map_err(io)
    })();
    if result.is_err() {
        p.storage.stage_abort();
    }
    result
}
pub fn meta(p: &mut Platform<'_>, role: usize) -> Result<[u8; META_LEN], Error> {
    let mut b = [0; META_LEN];
    p.storage.read_at(KEYS[role], 0, &mut b).map_err(io)?;
    if b[0] != 1 || b[1] > 8 || b[2] > 2 || b[3] > 2 {
        return Err(Error::Storage);
    }
    let a = Algorithm(b[1]);
    let material = if b[2] == 0 {
        0
    } else {
        key_storage::length(a.rsa(), a.scalar())
    };
    if p.storage.size(KEYS[role]).map_err(io)? != (META_LEN + material) as u32 {
        return Err(Error::Storage);
    }
    Ok(b)
}
pub fn put_meta(p: &mut Platform<'_>, role: usize, b: &[u8; META_LEN]) -> Result<(), Error> {
    p.storage.replace_at(KEYS[role], 0, b).map_err(io)
}
pub fn load_key(p: &mut Platform<'_>, role: usize, b: &mut [u8; 1284]) -> Result<Algorithm, Error> {
    let m = meta(p, role)?;
    if m[2] == 0 {
        return Err(Error::Missing);
    }
    let a = Algorithm(m[1]);
    key_storage::load(
        p.storage,
        KEYS[role],
        META_LEN as u32,
        a.rsa(),
        a.scalar(),
        b,
    )
    .map_err(io)?;
    Ok(a)
}
pub fn save_key(
    p: &mut Platform<'_>,
    role: usize,
    origin: u8,
    b: &[u8; 1284],
) -> Result<(), Error> {
    let mut m = meta(p, role)?;
    m[2] = origin;
    // Signature counter belongs to this key, published in the same transaction.
    if role == 0 {
        m[28..31].fill(0);
    }
    let result = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(&m).map_err(io)?;
        let a = Algorithm(m[1]);
        key_storage::append(p.storage, a.rsa(), a.scalar(), b).map_err(io)?;
        p.storage.stage_commit(KEYS[role]).map_err(io)
    })();
    if result.is_err() {
        p.storage.stage_abort()
    }
    result
}
pub fn reset(p: &mut Platform<'_>) -> Result<(), Error> {
    let mut s = [0; STATE_LEN];
    s[0] = 1;
    s[1] = 1;
    save_state(p, &s)?; // Incomplete reset stays terminated and can be retried.
    pin::create(Record::PgpPw1, b"123456", 3, p)?;
    pin::create(Record::PgpPw3, b"12345678", 3, p)?;
    pin::create(Record::PgpRc, b"", 3, p)?;
    for i in 0..3 {
        let mut m = [0; META_LEN];
        m[0] = 1;
        m[1] = 5;
        p.storage.replace(KEYS[i], &m).map_err(io)?;
        p.storage.replace(CERTS[i], &[]).map_err(io)?;
    }
    s[181] = 1;
    s[182] = b'9';
    s[1] = 0;
    save_state(p, &s)
}
pub fn install(p: &mut Platform<'_>) -> Result<(), Error> {
    let mut s = [0; STATE_LEN];
    match p.storage.load(Record::PgpState, &mut s) {
        Err(StorageError::Missing) => reset(p),
        Ok(_) => state(p, &mut s),
        Err(e) => Err(io(e)),
    }
}

pub fn terminated(p: &mut Platform<'_>) -> Result<bool, Error> {
    let mut bytes = [0; 2];
    p.storage
        .read_at(Record::PgpState, 0, &mut bytes)
        .map_err(io)?;
    if bytes[0] != 1 {
        return Err(Error::Storage);
    }
    Ok(bytes[1] != 0)
}
