// SPDX-License-Identifier: Apache-2.0
//! Fixed state fields and cold key material followed by hot metadata.
use super::domain::Error;
use super::domain::key_role;
use super::wire::tag;
use super::{domain::Algorithm, pin};
use crate::mechanisms::key_storage;
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_ports::Storage as _;
// Byte offsets shared by the fixed disk record and the RAM view.
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
// Byte offsets within the key metadata footer. CREATED holds four protocol bytes
// (big-endian creation time); SIGNATURE_COUNTER is a three-byte big-endian count.
// ORIGIN distinguishes absent (0), generated (1), and imported (2) keys.
pub mod key_meta {
    pub const VERSION: usize = 0;
    pub const ALGORITHM: usize = 1;
    pub const ORIGIN: usize = 2;
    pub const ORIGIN_ABSENT: u8 = 0x00;
    pub const ORIGIN_GENERATED: u8 = 0x01;
    pub const ORIGIN_IMPORTED: u8 = 0x02;
    pub const TOUCH_POLICY: usize = 3;
    pub const FINGERPRINT: usize = 4;
    pub const FINGERPRINT_END: usize = 24;
    pub const CREATED: usize = FINGERPRINT_END;
    pub const CREATED_END: usize = 28;
    pub const SIGNATURE_COUNTER: usize = CREATED_END;
    pub const END: usize = 31;
}
const FORMAT_VERSION: u8 = 2;
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
pub fn state(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    b: &mut [u8; STATE_LEN],
) -> Result<(), Error> {
    let n = p.storage.load(Record::PgpState, b).map_err(io)?;
    validate_state(b, n)
}
fn validate_state(b: &mut [u8; STATE_LEN], n: usize) -> Result<(), Error> {
    if n != state_layout::USED_END
        || b[state_layout::VERSION] != FORMAT_VERSION
        || b[state_layout::TERMINATED] > 1
        || b[state_layout::PW1_REUSE] > 1
    {
        return Err(Error::Storage);
    }
    for (_, off, max) in FIELDS {
        if b[off] as usize > max {
            return Err(Error::Storage);
        }
    }
    b[state_layout::USED_END..].fill(0);
    Ok(())
}
pub fn save_state(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    b: &[u8; STATE_LEN],
) -> Result<(), Error> {
    p.storage
        .replace(Record::PgpState, &b[..state_layout::USED_END])
        .map_err(io)
}
pub fn meta(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    role: usize,
) -> Result<[u8; META_LEN], Error> {
    // Check the leading discriminator before interpreting a metadata footer.
    // Never read private components merely to access hot metadata.
    let n = p.storage.size(KEYS[role]).map_err(io)?;
    let mut b = [0; META_LEN];
    let valid =
        key_storage::read_footer(p.storage, KEYS[role], n, FORMAT_VERSION, &mut b, |b, n| {
            if b[key_meta::VERSION] != FORMAT_VERSION
                || b[key_meta::ORIGIN] > key_meta::ORIGIN_IMPORTED
                || b[key_meta::TOUCH_POLICY] > 2
            {
                return false;
            }
            let a = Algorithm(b[key_meta::ALGORITHM]);
            if a.private_component_bytes() == 0 {
                return false;
            }
            let material = if b[key_meta::ORIGIN] == key_meta::ORIGIN_ABSENT {
                0
            } else {
                key_storage::length(a.rsa(), a.private_component_bytes())
            };
            n == (1 + META_LEN + material) as u32
        })
        .map_err(io)?;
    if !valid {
        return Err(Error::Storage);
    }
    Ok(b)
}
pub fn put_meta(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    role: usize,
    b: &[u8; META_LEN],
) -> Result<(), Error> {
    let a = Algorithm(b[key_meta::ALGORITHM]);
    let material = if b[key_meta::ORIGIN] == key_meta::ORIGIN_ABSENT {
        0
    } else {
        key_storage::length(a.rsa(), a.private_component_bytes())
    };
    p.storage
        .replace_at(KEYS[role], (1 + material) as u32, b)
        .map_err(io)
}
pub fn empty_key(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    role: usize,
    m: &[u8; META_LEN],
) -> Result<(), Error> {
    let mut record = [FORMAT_VERSION; 1 + META_LEN];
    record[1..].copy_from_slice(m);
    p.storage.replace(KEYS[role], &record).map_err(io)
}
pub fn load_key(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    role: usize,
    b: &mut [u8; crate::ports::key_layout::SIZE],
) -> Result<Algorithm, Error> {
    let m = meta(p, role)?;
    if m[key_meta::ORIGIN] == key_meta::ORIGIN_ABSENT {
        return Err(Error::Missing);
    }
    let a = Algorithm(m[key_meta::ALGORITHM]);
    key_storage::load(
        p.storage,
        KEYS[role],
        1,
        a.rsa(),
        a.private_component_bytes(),
        b,
    )
    .map_err(io)?;
    Ok(a)
}
pub fn save_key(
    p: &mut Platform<'_, impl crate::ports::Backends>,
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
    let a = Algorithm(m[key_meta::ALGORITHM]);
    key_storage::commit(
        p.storage,
        KEYS[role],
        a.rsa(),
        a.private_component_bytes(),
        b,
        &m,
    )
    .map_err(io)
}
pub fn reset(p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<(), Error> {
    let mut s = [0; STATE_LEN];
    s[state_layout::VERSION] = FORMAT_VERSION;
    s[state_layout::TERMINATED] = 1;
    save_state(p, &s)?; // Incomplete reset stays terminated and can be retried.
    pin::create(Record::PgpPw1, pin::DEFAULT_PW1, pin::DEFAULT_RETRIES, p)?;
    pin::create(Record::PgpPw3, pin::DEFAULT_PW3, pin::DEFAULT_RETRIES, p)?;
    pin::create(Record::PgpRc, b"", pin::DEFAULT_RETRIES, p)?;
    for i in 0..key_role::COUNT {
        let mut m = [0; META_LEN];
        m[key_meta::VERSION] = FORMAT_VERSION;
        m[key_meta::ALGORITHM] = crate::ports::alg::RSA2048;
        empty_key(p, i, &m)?;
        p.storage.replace(CERTS[i], &[]).map_err(io)?;
    }
    s[state_layout::SEX] = 1;
    s[state_layout::SEX + 1] = b'9'; // ISO 5218: sex not applicable.
    s[state_layout::TERMINATED] = 0;
    save_state(p, &s)
}
pub fn install(p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<(), Error> {
    let mut s = [0; STATE_LEN];
    crate::mechanisms::storage::load_or_else(
        p,
        Record::PgpState,
        &mut s,
        validate_state,
        |_, p| reset(p),
        io,
    )
}

pub fn terminated(p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<bool, Error> {
    let mut bytes = [0; 2];
    p.storage
        .read_at(Record::PgpState, 0, &mut bytes)
        .map_err(io)?;
    if bytes[state_layout::VERSION] != FORMAT_VERSION {
        return Err(Error::Storage);
    }
    Ok(bytes[state_layout::TERMINATED] != 0)
}
