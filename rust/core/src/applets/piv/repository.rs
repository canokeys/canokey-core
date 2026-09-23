// SPDX-License-Identifier: Apache-2.0
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_protocol::response::StatusWord as Sw;
pub const SLOTS: [u8; 25] = [
    0x9a, 0x9c, 0x9d, 0x9e, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
    0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xf9,
];
pub const KEYS: [Record; 25] = [
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
// Versioned key-record header. Keep offsets stable for existing cards.
pub const META: usize = 88;
pub const ALGORITHM: usize = 1;
pub const ORIGIN: usize = 2;
pub const PIN_POLICY: usize = 3;
pub const TOUCH_POLICY: usize = 4;
pub const NAME_LENGTH: usize = 5;
pub const NAME: usize = 8;
pub const DEFAULT_CONFIG: [u8; 10] = [1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3];
pub const DEFAULT_MGMT: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];
pub fn io(_: StorageError) -> Sw {
    Sw::UNABLE_TO_PROCESS
}
pub fn slot(id: u8) -> Result<usize, Sw> {
    SLOTS.iter().position(|s| *s == id).ok_or(Sw::WRONG_P1P2)
}
pub fn width(a: u8) -> usize {
    [32, 32, 48, 32, 32, 128, 192, 256, 66, 32, 64, 32]
        .get(a as usize)
        .copied()
        .unwrap_or(0)
}
pub fn rsa(a: u8) -> bool {
    (5..=7).contains(&a)
}
pub fn material(a: u8) -> usize {
    if rsa(a) { 1284 } else { width(a) }
}
pub fn algorithm(id: u8, c: &[u8; 10]) -> Result<u8, Sw> {
    match id {
        0x11 => return Ok(0),
        0x14 => return Ok(2),
        7 => return Ok(5),
        _ => (),
    };
    if c[0] != 0 {
        for (i, a) in [3, 6, 7, 4, 1, 8, 9, 11, 10].iter().enumerate() {
            if c[i + 1] == id {
                return Ok(*a);
            }
        }
    }
    Err(Sw::WRONG_DATA)
}
pub fn algorithm_id(a: u8, c: &[u8; 10]) -> u8 {
    match a {
        0 => 0x11,
        2 => 0x14,
        5 => 7,
        _ => [3, 6, 7, 4, 1, 8, 9, 11, 10]
            .iter()
            .position(|v| *v == a)
            .map_or(0, |i| c[i + 1]),
    }
}
pub fn config_valid(c: &[u8]) -> bool {
    c.len() == 10
        && c[0] <= 1
        && (c[0] == 0
            || c[1..].iter().enumerate().all(|(i, v)| {
                !matches!(*v, 0 | 8 | 7 | 0x11 | 0x14 | 0xff) && !c[1..i + 1].contains(v)
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
        m[0] = 1;
        m[ALGORITHM] = 0xff;
        m[PIN_POLICY] = match SLOTS[id] {
            0x9c => 3,
            0x9e | 0xf9 => 1,
            _ => 2,
        };
        m[TOUCH_POLICY] = 1;
        return Ok(m);
    }
    p.storage.read_at(KEYS[id], 0, &mut m).map_err(io)?;
    if m[0] != 1
        || m[ALGORITHM] > 11
        || !(1..=2).contains(&m[ORIGIN])
        || !(1..=3).contains(&m[PIN_POLICY])
        || m[TOUCH_POLICY] > 3
        || m[NAME_LENGTH] > 78
        || n as usize != META + material(m[ALGORITHM])
    {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    Ok(m)
}
pub fn load(
    id: usize,
    m: &[u8; META],
    key: &mut [u8; 1284],
    p: &mut Platform<'_>,
) -> Result<(), Sw> {
    if m[ORIGIN] == 0 {
        return Err(Sw(0x6a88));
    }
    p.storage
        .read_at(KEYS[id], META as u32, &mut key[..material(m[ALGORITHM])])
        .map_err(io)
}
pub fn save(id: usize, m: &[u8; META], key: &[u8; 1284], p: &mut Platform<'_>) -> Result<(), Sw> {
    let r = (|| {
        p.storage.stage_begin().map_err(io)?;
        p.storage.stage_append(m).map_err(io)?;
        p.storage
            .stage_append(&key[..material(m[ALGORITHM])])
            .map_err(io)?;
        p.storage.stage_commit(KEYS[id]).map_err(io)
    })();
    if r.is_err() {
        p.storage.stage_abort()
    }
    r
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
    if !matches!(t, 0xaa | 0xab) || v > 3 {
        return Err(Sw::WRONG_DATA);
    }
    if v != 0 {
        m[if t == 0xaa { PIN_POLICY } else { TOUCH_POLICY }] = v;
    }
    Ok(())
}
/// Object index, capacity, PIN-read gate, certificate flag.
pub fn object(tag: u32) -> Option<(usize, usize, bool, bool)> {
    let cert = match tag {
        0x5fc105 => Some(0),
        0x5fc10a => Some(1),
        0x5fc10b => Some(2),
        0x5fc101 => Some(3),
        0x5fc10d..=0x5fc120 => Some(4 + (tag - 0x5fc10d) as usize),
        0x5fff01 => Some(24),
        _ => None,
    };
    if let Some(i) = cert {
        return Some((i, 6568, false, true));
    }
    let (i, pin) = match tag {
        0x5fc102 => (25, false),
        0x5fc103 => (26, true),
        0x5fc106 => (27, false),
        0x5fc107 => (28, false),
        0x5fc108 => (29, true),
        0x5fc109 => (30, true),
        0x5fc10c => (31, false),
        0x5fc121 => (32, true),
        0x5fff00 => (33, false),
        _ => return None,
    };
    Some((i, if i == 33 { 128 } else { 3040 }, pin, false))
}
pub fn management(p: &mut Platform<'_>) -> Result<[u8; 26], Sw> {
    let mut b = [0; 26];
    if p.storage.load(Record::PivManagement, &mut b).map_err(io)? != 26
        || b[0] != 1
        || !matches!(b[1], 1 | 2)
    {
        p.memory.wipe(&mut b);
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    Ok(b)
}
