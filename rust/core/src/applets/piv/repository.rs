// SPDX-License-Identifier: Apache-2.0
use super::wire::{key_tag, limits, object_tag, policy, slot, wire_alg};
use crate::mechanisms::key_storage;
use crate::ports::alg;
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_protocol::response::StatusWord as Sw;
pub const SLOTS: [u8; KEY_COUNT] = [
    slot::AUTHENTICATION,
    slot::SIGNATURE,
    slot::KEY_MANAGEMENT,
    slot::CARD_AUTHENTICATION,
    0x82,
    0x83,
    0x84,
    0x85,
    0x86,
    0x87,
    0x88,
    0x89,
    0x8a,
    0x8b,
    0x8c,
    0x8d,
    0x8e,
    0x8f,
    0x90,
    0x91,
    0x92,
    0x93,
    0x94,
    0x95,
    slot::ATTESTATION,
];
pub const KEYS: [Record; KEY_COUNT] = [
    Record::PivKey0,
    Record::PivKey1,
    Record::PivKey2,
    Record::PivKey3,
    Record::PivKey4,
    Record::PivKey5,
    Record::PivKey6,
    Record::PivKey7,
    Record::PivKey8,
    Record::PivKey9,
    Record::PivKey10,
    Record::PivKey11,
    Record::PivKey12,
    Record::PivKey13,
    Record::PivKey14,
    Record::PivKey15,
    Record::PivKey16,
    Record::PivKey17,
    Record::PivKey18,
    Record::PivKey19,
    Record::PivKey20,
    Record::PivKey21,
    Record::PivKey22,
    Record::PivKey23,
    Record::PivKey24,
];
pub const OBJECTS: [Record; 34] = [
    Record::PivObject0,
    Record::PivObject1,
    Record::PivObject2,
    Record::PivObject3,
    Record::PivObject4,
    Record::PivObject5,
    Record::PivObject6,
    Record::PivObject7,
    Record::PivObject8,
    Record::PivObject9,
    Record::PivObject10,
    Record::PivObject11,
    Record::PivObject12,
    Record::PivObject13,
    Record::PivObject14,
    Record::PivObject15,
    Record::PivObject16,
    Record::PivObject17,
    Record::PivObject18,
    Record::PivObject19,
    Record::PivObject20,
    Record::PivObject21,
    Record::PivObject22,
    Record::PivObject23,
    Record::PivObject24,
    Record::PivObject25,
    Record::PivObject26,
    Record::PivObject27,
    Record::PivObject28,
    Record::PivObject29,
    Record::PivObject30,
    Record::PivObject31,
    Record::PivObject32,
    Record::PivObject33,
];
// Byte offsets in the RAM metadata view (META is its byte capacity).
// Disk stores six header bytes, key material, then only the used UTF-16LE name.
// NAME_LENGTH counts bytes, not characters. ORIGIN is 0 absent / 1 generated /
// 2 imported; PIN_POLICY and TOUCH_POLICY use wire::policy values.
pub const VERSION: usize = 0;
pub const FORMAT_VERSION: u8 = 1;
pub const NAME_MAX: usize = 78;
pub const USER_KEY_COUNT: usize = 24;
pub const ATTESTATION_KEY: usize = USER_KEY_COUNT;
pub const KEY_COUNT: usize = USER_KEY_COUNT + 1;
pub const HEADER: usize = 6;
pub const META: usize = 88;
const P256_BYTES: usize = 32;
const P384_BYTES: usize = 48;
const P521_BYTES: usize = 66;
const RSA2048_COMPONENT_BYTES: usize = 128;
const RSA3072_COMPONENT_BYTES: usize = 192;
const RSA4096_COMPONENT_BYTES: usize = 256;
const MLKEM_SEED_BYTES: usize = 64;
pub const ALGORITHM: usize = 1;
pub const ORIGIN: usize = 2;
pub const PIN_POLICY: usize = 3;
pub const TOUCH_POLICY: usize = 4;
pub const NAME_LENGTH: usize = 5;
pub const NAME: usize = 8;
// Algorithm-mapping record: enable byte, then nine wire IDs in the order of
// EXTENSION_ALGORITHMS below. These values are APDU IDs, not ports::alg IDs.
pub const DEFAULT_CONFIG: [u8; 10] = [0x01, 0xe0, 0x05, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3];
pub const DEFAULT_MGMT: [u8; MANAGEMENT_KEY_BYTES] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
pub fn io(_: StorageError) -> Sw {
    Sw::UNABLE_TO_PROCESS
}
pub fn slot(id: u8) -> Result<usize, Sw> {
    SLOTS.iter().position(|s| *s == id).ok_or(Sw::WRONG_P1P2)
}
// Private component size in bytes, indexed by ports::alg: EC scalar, one RSA
// prime/CRT component (half the modulus width), or a persisted PQ seed.
pub fn width(a: u8) -> usize {
    match a {
        alg::P256 | alg::SECP256K1 | alg::ED25519 | alg::X25519 | alg::SM2 | alg::MLDSA65 => {
            P256_BYTES
        }
        alg::P384 => P384_BYTES,
        alg::RSA2048 => RSA2048_COMPONENT_BYTES,
        alg::RSA3072 => RSA3072_COMPONENT_BYTES,
        alg::RSA4096 => RSA4096_COMPONENT_BYTES,
        alg::P521 => P521_BYTES,
        alg::MLKEM768 => MLKEM_SEED_BYTES,
        _ => 0,
    }
}
pub fn rsa(a: u8) -> bool {
    (alg::RSA2048..=alg::RSA4096).contains(&a)
}
pub fn material(a: u8) -> usize {
    key_storage::length(rsa(a), width(a))
}
// Configuration bytes 1..9 assign wire IDs in this stable order.
const EXTENSION_ALGORITHMS: [u8; 9] = [
    alg::ED25519,
    alg::RSA3072,
    alg::RSA4096,
    alg::X25519,
    alg::SECP256K1,
    alg::P521,
    alg::SM2,
    alg::MLDSA65,
    alg::MLKEM768,
];
pub fn algorithm(id: u8, c: &[u8; 10]) -> Result<u8, Sw> {
    match id {
        wire_alg::P256 => return Ok(alg::P256),
        wire_alg::P384 => return Ok(alg::P384),
        wire_alg::RSA2048 => return Ok(alg::RSA2048),
        _ => (),
    };
    // Configuration byte 0 enables vendor algorithms. Standard PIV IDs above
    // remain available even when extensions are disabled.
    if c[0] != 0 {
        for (i, a) in EXTENSION_ALGORITHMS.iter().enumerate() {
            if c[i + 1] == id {
                return Ok(*a);
            }
        }
    }
    Err(Sw::WRONG_DATA)
}
pub fn algorithm_id(a: u8, c: &[u8; 10]) -> u8 {
    match a {
        alg::P256 => wire_alg::P256,
        alg::P384 => wire_alg::P384,
        alg::RSA2048 => wire_alg::RSA2048,
        _ => EXTENSION_ALGORITHMS
            .iter()
            .position(|v| *v == a)
            .map_or(0, |i| c[i + 1]),
    }
}
// Disabled mappings may retain inactive values. Enabled mappings must avoid
// standard/reserved wire IDs and duplicate extension IDs; otherwise dispatch
// could silently select a different algorithm from the one requested.
pub fn config_valid(c: &[u8]) -> bool {
    c.len() == 10
        && c[0] <= 1
        && (c[0] == 0
            || c[1..].iter().enumerate().all(|(i, v)| {
                !matches!(
                    *v,
                    wire_alg::DEFAULT
                        | wire_alg::AES192
                        | wire_alg::RSA2048
                        | wire_alg::P256
                        | wire_alg::P384
                        | wire_alg::ED25519_STREAM
                ) && !c[1..i + 1].contains(v)
            }))
}
pub fn meta(id: usize, p: &mut Platform<'_>) -> Result<[u8; META], Sw> {
    let mut m = [0; META];
    let n = match p.storage.size(KEYS[id]) {
        Err(StorageError::Missing) => 0,
        Ok(n) => n,
        Err(e) => return Err(io(e)),
    };
    if n == 0 {
        m[VERSION] = FORMAT_VERSION;
        m[ALGORITHM] = 0xff;
        m[PIN_POLICY] = match SLOTS[id] {
            slot::SIGNATURE => policy::PIN_ALWAYS,
            slot::CARD_AUTHENTICATION | slot::ATTESTATION => policy::PIN_NEVER,
            _ => policy::PIN_ONCE,
        };
        m[TOUCH_POLICY] = policy::TOUCH_NEVER;
        return Ok(m);
    }
    p.storage
        .read_at(KEYS[id], 0, &mut m[..HEADER])
        .map_err(io)?;
    if m[VERSION] != FORMAT_VERSION
        || m[ALGORITHM] > alg::MLDSA65
        || !(1..=2).contains(&m[ORIGIN])
        || !(policy::PIN_NEVER..=policy::PIN_ALWAYS).contains(&m[PIN_POLICY])
        || m[TOUCH_POLICY] > policy::TOUCH_CACHED
        || m[NAME_LENGTH] > NAME_MAX as u8
        || n as usize != HEADER + material(m[ALGORITHM]) + m[NAME_LENGTH] as usize
    {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    let name_len = m[NAME_LENGTH] as usize;
    p.storage
        .read_at(
            KEYS[id],
            (HEADER + material(m[ALGORITHM])) as u32,
            &mut m[NAME..NAME + name_len],
        )
        .map_err(io)?;
    Ok(m)
}
pub fn load(
    id: usize,
    m: &[u8; META],
    key: &mut [u8; crate::ports::key_layout::SIZE],
    p: &mut Platform<'_>,
) -> Result<(), Sw> {
    if m[ORIGIN] == 0 {
        return Err(Sw::REFERENCE_NOT_FOUND);
    }
    let a = m[ALGORITHM];
    key_storage::load(p.storage, KEYS[id], HEADER as u32, rsa(a), width(a), key).map_err(io)
}
pub fn save(
    id: usize,
    m: &[u8; META],
    key: &[u8; crate::ports::key_layout::SIZE],
    p: &mut Platform<'_>,
) -> Result<(), Sw> {
    let r = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(&m[..HEADER]).map_err(io)?;
        let a = m[ALGORITHM];
        key_storage::append(p.storage, rsa(a), width(a), key).map_err(io)?;
        p.storage
            .stage_append(&m[NAME..NAME + m[NAME_LENGTH] as usize])
            .map_err(io)?;
        p.storage.stage_commit(KEYS[id]).map_err(io)
    })();
    if r.is_err() {
        p.storage.stage_abort()
    }
    r
}
pub fn save_name(id: usize, m: &[u8; META], p: &mut Platform<'_>) -> Result<(), Sw> {
    let result = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(&m[..HEADER]).map_err(io)?;
        crate::ports::copy_to_stage(
            p.storage,
            p.memory,
            KEYS[id],
            HEADER as u32,
            material(m[ALGORITHM]) as u32,
        )
        .map_err(io)?;
        p.storage
            .stage_append(&m[NAME..NAME + m[NAME_LENGTH] as usize])
            .map_err(io)?;
        p.storage.stage_commit(KEYS[id]).map_err(io)
    })();
    if result.is_err() {
        p.storage.stage_abort();
    }
    result
}
pub fn policies(m: &mut [u8; META], mut b: &[u8]) -> Result<(), Sw> {
    while !b.is_empty() {
        let (t, v) = super::codec::take(&mut b)?;
        if v.len() != 1 {
            return Err(Sw::WRONG_LENGTH);
        }
        policy(m, t, v[0])?;
    }
    Ok(())
}
pub fn policy(m: &mut [u8; META], t: u8, v: u8) -> Result<(), Sw> {
    if !matches!(t, key_tag::PIN_POLICY | key_tag::TOUCH_POLICY) || v > policy::TOUCH_CACHED {
        return Err(Sw::WRONG_DATA);
    }
    if v != policy::DEFAULT {
        m[if t == key_tag::PIN_POLICY {
            PIN_POLICY
        } else {
            TOUCH_POLICY
        }] = v;
    }
    Ok(())
}
/// Storage policy for a PIV data object. The tag is a wire identifier; index
/// selects OBJECTS and is not itself a Record ID or a byte offset.
pub struct ObjectDescriptor {
    pub index: usize,
    pub capacity_bytes: usize,
    pub requires_pin: bool,
}
// Existing object quotas, including their stored TLV wrappers. These are flash
// object limits, not sizes of the shared APDU buffer.
const DATA_OBJECT_CAPACITY_BYTES: usize = 3040;
const ADMIN_OBJECT_CAPACITY_BYTES: usize = 128;
pub const CHUID_OBJECT_INDEX: usize = 25;
pub const CAPABILITY_OBJECT_INDEX: usize = 28;
const ADMIN_OBJECT_INDEX: usize = 33;

pub fn object(tag: u32) -> Option<ObjectDescriptor> {
    let cert = match tag {
        object_tag::CERT_AUTHENTICATION => Some(0),
        object_tag::CERT_SIGNATURE => Some(1),
        object_tag::CERT_KEY_MANAGEMENT => Some(2),
        object_tag::CERT_CARD_AUTHENTICATION => Some(3),
        object_tag::CERT_RETIRED_FIRST..=object_tag::CERT_RETIRED_LAST => {
            Some(4 + (tag - object_tag::CERT_RETIRED_FIRST) as usize)
        }
        object_tag::CERT_ATTESTATION => Some(ATTESTATION_KEY),
        _ => None,
    };
    if let Some(i) = cert {
        return Some(ObjectDescriptor {
            index: i,
            capacity_bytes: limits::CERTIFICATE_OBJECT_BYTES,
            requires_pin: false,
        });
    }
    let (i, pin) = match tag {
        object_tag::CHUID => (CHUID_OBJECT_INDEX, false),
        object_tag::FINGERPRINTS => (26, true),
        object_tag::SECURITY => (27, false),
        object_tag::CAPABILITY => (CAPABILITY_OBJECT_INDEX, false),
        object_tag::FACIAL_IMAGE => (29, true),
        object_tag::PRINTED_INFORMATION => (30, true),
        object_tag::KEY_HISTORY => (31, false),
        object_tag::IRIS_IMAGES => (32, true),
        object_tag::ADMIN => (ADMIN_OBJECT_INDEX, false),
        _ => return None,
    };
    Some(ObjectDescriptor {
        index: i,
        capacity_bytes: if i == ADMIN_OBJECT_INDEX {
            ADMIN_OBJECT_CAPACITY_BYTES
        } else {
            DATA_OBJECT_CAPACITY_BYTES
        },
        requires_pin: pin,
    })
}
pub const MANAGEMENT_KEY_BYTES: usize = 24;
pub const MANAGEMENT_SIZE: usize = MANAGEMENT_KEY + MANAGEMENT_KEY_BYTES;
pub const MANAGEMENT_TOUCH: usize = 1;
pub const MANAGEMENT_KEY: usize = 2;
pub fn management_record(touch: u8, key: &[u8]) -> [u8; MANAGEMENT_SIZE] {
    let mut record = [0; MANAGEMENT_SIZE];
    record[VERSION] = FORMAT_VERSION; // Format version.
    record[MANAGEMENT_TOUCH] = touch;
    record[MANAGEMENT_KEY..].copy_from_slice(key);
    record
}
pub fn management(p: &mut Platform<'_>) -> Result<[u8; MANAGEMENT_SIZE], Sw> {
    let mut b = [0; MANAGEMENT_SIZE];
    if p.storage.load(Record::PivManagement, &mut b).map_err(io)? != MANAGEMENT_SIZE
        || b[VERSION] != FORMAT_VERSION
        || !matches!(
            b[MANAGEMENT_TOUCH],
            policy::TOUCH_NEVER | policy::TOUCH_ALWAYS
        )
    {
        p.memory.wipe(&mut b);
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    Ok(b)
}
