// SPDX-License-Identifier: Apache-2.0
//! Compact records; fixed field offsets are an in-memory view only.
use super::domain::Error;
use super::domain::key_role;
use super::wire::tag;
use super::{domain::Algorithm, pin};
use crate::mechanisms::key_storage;
use crate::{
    Platform,
    ports::{Record, StorageError},
};
// Byte offsets in the expanded RAM view, not offsets in the compact disk record.
// *_END values are exclusive. NAME/LOGIN/LANGUAGE/SEX/URL point to a one-byte
// length followed by a fixed-capacity value; *_MAX excludes that length byte.
// CA means certification authority; each stored OpenPGP fingerprint is 20 bytes.
pub mod state_layout {
    pub const VERSION: usize = 0;
    pub const TERMINATED: usize = 1;
    pub const PW1_REUSE: usize = 2;
    pub const TOUCH_CACHE_SECONDS: usize = 3;
    pub const FLAGS_END: usize = 4;
    pub const CA_FINGERPRINTS: usize = 8;
    pub const FINGERPRINT_BYTES: usize = 20;
    pub const CA_FINGERPRINTS_END: usize = CA_FINGERPRINTS + 3 * FINGERPRINT_BYTES;
    pub const NAME: usize = CA_FINGERPRINTS_END;
    pub const NAME_MAX: usize = 39;
    pub const LOGIN: usize = NAME + 1 + NAME_MAX;
    pub const LOGIN_MAX: usize = 63;
    pub const LANGUAGE: usize = LOGIN + 1 + LOGIN_MAX;
    pub const LANGUAGE_MAX: usize = 8;
    pub const SEX: usize = LANGUAGE + 1 + LANGUAGE_MAX;
    pub const URL: usize = SEX + 2;
    pub const URL_MAX: usize = 255;
    pub const USED_END: usize = URL + 1 + URL_MAX;
}
// Byte offsets in the key metadata prefix. CREATED holds four protocol bytes
// (big-endian creation time); SIGNATURE_COUNTER is a three-byte big-endian count.
// ORIGIN distinguishes absent (0), generated (1), and imported (2) keys.
pub mod key_meta {
    pub const VERSION: usize = 0;
    pub const ALGORITHM: usize = 1;
    pub const ORIGIN: usize = 2;
    pub const TOUCH_POLICY: usize = 3;
    pub const FINGERPRINT: usize = 4;
    pub const FINGERPRINT_END: usize = 24;
    pub const CREATED: usize = FINGERPRINT_END;
    pub const CREATED_END: usize = 28;
    pub const SIGNATURE_COUNTER: usize = CREATED_END;
    pub const END: usize = 31;
}
const FORMAT_VERSION: u8 = 1;
pub const STATE_LEN: usize = 512;
pub const META_LEN: usize = key_meta::END;
pub const KEYS: [Record; 3] = [Record::PgpSig, Record::PgpDec, Record::PgpAut];
pub const CERTS: [Record; 3] = [Record::PgpCertSig, Record::PgpCertDec, Record::PgpCertAut];
pub fn io(_: StorageError) -> Error {
    Error::Storage
}
// State: version, terminated, PW1 reuse, cache seconds, reserved[4];
// CA fingerprints[60]; length-prefixed name(39), login(63), lang(8), sex(1), URL(255).
pub fn field(tag: u16) -> Option<(usize, usize)> {
    FIELDS
        .iter()
        .find_map(|(candidate, off, max)| (*candidate == tag).then_some((*off, *max)))
}
const FIELDS: [(u16, usize, usize); 5] = [
    (tag::NAME, state_layout::NAME, state_layout::NAME_MAX),
    (tag::LOGIN, state_layout::LOGIN, state_layout::LOGIN_MAX),
    (
        tag::LANGUAGE,
        state_layout::LANGUAGE,
        state_layout::LANGUAGE_MAX,
    ),
    (tag::SEX, state_layout::SEX, 1),
    (tag::URL, state_layout::URL, state_layout::URL_MAX),
];
const STATE_HEADER: usize = state_layout::FLAGS_END + 3 * state_layout::FINGERPRINT_BYTES; // Four flags followed by three CA fingerprints.
pub fn state(p: &mut Platform<'_>, b: &mut [u8; STATE_LEN]) -> Result<(), Error> {
    let n = p.storage.load(Record::PgpState, b).map_err(io)?;
    if n < STATE_HEADER || b[state_layout::VERSION] != FORMAT_VERSION {
        return Err(Error::Storage);
    }
    let mut starts = [0; 5];
    let mut at = STATE_HEADER;
    for (i, (_, _, max)) in FIELDS.iter().enumerate() {
        if at >= n || b[at] as usize > *max || at + 1 + b[at] as usize > n {
            return Err(Error::Storage);
        }
        starts[i] = at;
        at += 1 + b[at] as usize;
    }
    if at != n {
        return Err(Error::Storage);
    }
    for (i, (_, off, max)) in FIELDS.iter().enumerate().rev() {
        let from = starts[i];
        let len = 1 + b[from] as usize;
        b.copy_within(from..from + len, *off);
        b[off + len..off + 1 + max].fill(0);
    }
    b.copy_within(
        state_layout::FLAGS_END..STATE_HEADER,
        state_layout::CA_FINGERPRINTS,
    );
    b[state_layout::FLAGS_END..state_layout::CA_FINGERPRINTS].fill(0);
    b[state_layout::USED_END..].fill(0);
    Ok(())
}
pub fn save_state(p: &mut Platform<'_>, b: &[u8; STATE_LEN]) -> Result<(), Error> {
    let result = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage
            .stage_append(&b[..state_layout::FLAGS_END])
            .map_err(io)?;
        p.storage
            .stage_append(&b[state_layout::CA_FINGERPRINTS..state_layout::CA_FINGERPRINTS_END])
            .map_err(io)?;
        for (_, off, max) in FIELDS {
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
    // A key record is bounded by key_layout::SIZE. Loading that bounded
    // record once lets us validate both the metadata prefix and the exact
    // material length without a second size query to storage.
    let mut record = [0; crate::ports::key_layout::SIZE];
    let n = p.storage.load(KEYS[role], &mut record).map_err(io)?;
    if n < META_LEN {
        return Err(Error::Storage);
    }
    let b: [u8; META_LEN] = record[..META_LEN].try_into().map_err(|_| Error::Storage)?;
    if b[key_meta::VERSION] != FORMAT_VERSION
        || b[key_meta::ORIGIN] > 2
        || b[key_meta::TOUCH_POLICY] > 2
    {
        return Err(Error::Storage);
    }
    let a = Algorithm(b[key_meta::ALGORITHM]);
    if a.private_component_bytes() == 0 {
        return Err(Error::Storage);
    }
    let material = if b[key_meta::ORIGIN] == 0 {
        0
    } else {
        key_storage::length(a.rsa(), a.private_component_bytes())
    };
    if n != META_LEN + material {
        return Err(Error::Storage);
    }
    Ok(b)
}
pub fn put_meta(p: &mut Platform<'_>, role: usize, b: &[u8; META_LEN]) -> Result<(), Error> {
    p.storage.replace_at(KEYS[role], 0, b).map_err(io)
}
pub fn load_key(
    p: &mut Platform<'_>,
    role: usize,
    b: &mut [u8; crate::ports::key_layout::SIZE],
) -> Result<Algorithm, Error> {
    let m = meta(p, role)?;
    if m[key_meta::ORIGIN] == 0 {
        return Err(Error::Missing);
    }
    let a = Algorithm(m[key_meta::ALGORITHM]);
    key_storage::load(
        p.storage,
        KEYS[role],
        META_LEN as u32,
        a.rsa(),
        a.private_component_bytes(),
        b,
    )
    .map_err(io)?;
    Ok(a)
}
pub fn save_key(
    p: &mut Platform<'_>,
    role: usize,
    origin: u8,
    b: &[u8; crate::ports::key_layout::SIZE],
) -> Result<(), Error> {
    let mut m = meta(p, role)?;
    m[key_meta::ORIGIN] = origin;
    // Signature counter belongs to this key, published in the same transaction.
    if role == key_role::SIGNATURE {
        m[key_meta::SIGNATURE_COUNTER..key_meta::END].fill(0);
    }
    let result = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(&m).map_err(io)?;
        let a = Algorithm(m[key_meta::ALGORITHM]);
        key_storage::append(p.storage, a.rsa(), a.private_component_bytes(), b).map_err(io)?;
        p.storage.stage_commit(KEYS[role]).map_err(io)
    })();
    if result.is_err() {
        p.storage.stage_abort()
    }
    result
}
pub fn reset(p: &mut Platform<'_>) -> Result<(), Error> {
    let mut s = [0; STATE_LEN];
    s[state_layout::VERSION] = FORMAT_VERSION;
    s[state_layout::TERMINATED] = 1;
    save_state(p, &s)?; // Incomplete reset stays terminated and can be retried.
    pin::create(Record::PgpPw1, b"123456", 3, p)?;
    pin::create(Record::PgpPw3, b"12345678", 3, p)?;
    pin::create(Record::PgpRc, b"", 3, p)?;
    for i in 0..key_role::COUNT {
        let mut m = [0; META_LEN];
        m[key_meta::VERSION] = FORMAT_VERSION;
        m[key_meta::ALGORITHM] = crate::ports::alg::RSA2048;
        p.storage.replace(KEYS[i], &m).map_err(io)?;
        p.storage.replace(CERTS[i], &[]).map_err(io)?;
    }
    s[state_layout::SEX] = 1;
    s[state_layout::SEX + 1] = b'9';
    s[state_layout::TERMINATED] = 0;
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
    if bytes[state_layout::VERSION] != FORMAT_VERSION {
        return Err(Error::Storage);
    }
    Ok(bytes[state_layout::TERMINATED] != 0)
}
