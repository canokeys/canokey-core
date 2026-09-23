// SPDX-License-Identifier: Apache-2.0
//! Key metadata, labels and slot movement.
use super::*;

impl Piv {
    pub(super) fn metadata(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        if h.p1 == 1 {
            if h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            w.output[..5].copy_from_slice(&[1, 1, 1, 2, 0]);
            let mut n = 5;
            for i in 0..24 {
                let m = repo::meta(i, p)?;
                let cert = match p.storage.size(repo::OBJECTS[i]) {
                    Err(StorageError::Missing) => false,
                    Ok(n) => n > 0,
                    Err(e) => return Err(repo::io(e)),
                };
                let flags = u8::from(m[repo::ORIGIN] != 0) | (u8::from(cert) * 2);
                if flags != 0 {
                    w.output[n..n + 6].copy_from_slice(&[
                        repo::SLOTS[i],
                        flags,
                        if m[repo::ORIGIN] != 0 {
                            repo::algorithm_id(m[repo::ALGORITHM], &self.config)
                        } else {
                            0
                        },
                        m[repo::ORIGIN],
                        if m[repo::ORIGIN] != 0 {
                            m[repo::PIN_POLICY]
                        } else {
                            0
                        },
                        if m[repo::ORIGIN] != 0 {
                            m[repo::TOUCH_POLICY]
                        } else {
                            0
                        },
                    ]);
                    n += 6;
                }
            }
            w.output[4] = (n - 5) as u8;
            self.memory(n);
            return Ok(n as u32);
        }
        if h.p1 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        if matches!(h.p2, 0x80 | 0x81) {
            self.pins.ready()?;
            let s = &self.pins.state;
            let (default, limit, remaining) = if h.p2 == 0x80 {
                (
                    s.pin == *crate::applets::piv::pin::PIN,
                    s.pin_limit,
                    s.pin_tries,
                )
            } else {
                (
                    s.puk == *crate::applets::piv::pin::PUK,
                    s.puk_limit,
                    s.puk_tries,
                )
            };
            w.output[..10].copy_from_slice(&[
                1,
                1,
                0xff,
                5,
                1,
                u8::from(default),
                6,
                2,
                limit,
                remaining,
            ]);
            self.memory(10);
            return Ok(10);
        }
        if h.p2 == 0x9b {
            let mut mgmt = repo::management(p)?;
            w.output[..10].copy_from_slice(&[
                1,
                1,
                8,
                2,
                2,
                0,
                mgmt[1],
                5,
                1,
                u8::from(mgmt[2..] == repo::DEFAULT_MGMT),
            ]);
            p.memory.wipe(&mut mgmt);
            self.memory(10);
            return Ok(10);
        }
        let id = repo::slot(h.p2).map_err(|_| Sw(0x6a88))?;
        let m = repo::meta(id, p)?;
        self.public(id, &m, true, w, p)
    }
    pub(super) fn name(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if h.p1 > 1 {
            return Err(Sw::WRONG_P1P2);
        }
        let id = repo::slot(h.p2)?;
        if h.p1 == 0 && self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        if h.p1 == 1 {
            self.authorized()?;
        }
        let mut m = repo::meta(id, p)?;
        if m[repo::ORIGIN] == 0 {
            return Err(Sw(0x6a88));
        }
        let n = m[repo::NAME_LENGTH] as usize;
        if h.p1 == 0 {
            w.output[..n].copy_from_slice(&m[repo::NAME..repo::NAME + n]);
            self.memory(n);
            return Ok(n as u32);
        }
        let value = &w.input[..self.used];
        if value.len() > 78 || !value.len().is_multiple_of(2) {
            return Err(Sw::WRONG_DATA);
        }
        let mut high = false;
        for pair in value.as_chunks::<2>().0 {
            let c = u16::from_le_bytes(*pair);
            if c == 0
                || (!high && (0xdc00..=0xdfff).contains(&c))
                || (high && !(0xdc00..=0xdfff).contains(&c))
            {
                return Err(Sw::WRONG_DATA);
            }
            high = !high && (0xd800..=0xdbff).contains(&c);
        }
        if high {
            return Err(Sw::WRONG_DATA);
        }
        if value == &m[repo::NAME..repo::NAME + n] {
            return Ok(0);
        }
        if !value.is_empty() {
            for other in 0..25 {
                if other == id {
                    continue;
                }
                let o = repo::meta(other, p)?;
                if o[repo::ORIGIN] != 0
                    && o[repo::NAME_LENGTH] as usize == value.len()
                    && value == &o[repo::NAME..repo::NAME + value.len()]
                {
                    return Err(Sw::WRONG_DATA);
                }
            }
        }
        m[repo::NAME_LENGTH] = value.len() as u8;
        m[repo::NAME..].fill(0);
        m[repo::NAME..repo::NAME + value.len()].copy_from_slice(value);
        repo::save_name(id, &m, p)?;
        Ok(0)
    }
    pub(super) fn move_key(&mut self, h: Header, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.authorized()?;
        if self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        let from = repo::slot(h.p2)?;
        if from == 24 {
            return Err(Sw::WRONG_P1P2);
        }
        if h.p1 == 0xff {
            p.storage.remove(repo::KEYS[from]).map_err(repo::io)?;
            return Ok(0);
        }
        let to = repo::slot(h.p1)?;
        if to == 24 {
            return Err(Sw::WRONG_P1P2);
        }
        if repo::meta(from, p)?[repo::ORIGIN] == 0 {
            return Err(Sw(0x6a88));
        }
        if repo::meta(to, p)?[repo::ORIGIN] != 0 {
            return Err(Sw::WRONG_DATA);
        }
        p.storage
            .move_record(repo::KEYS[from], repo::KEYS[to])
            .map_err(repo::io)?;
        Ok(0)
    }
}
