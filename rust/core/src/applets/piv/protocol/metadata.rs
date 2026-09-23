// SPDX-License-Identifier: Apache-2.0
//! Key metadata, labels and slot movement.
use super::*;

// Inventory extension: version TLV followed by a packed slot-list TLV.
const INVENTORY_VERSION_TAG: u8 = 0x01;
const INVENTORY_SLOTS_TAG: u8 = 0x02;
const INVENTORY_VERSION: u8 = 0x01;
const INVENTORY_HEADER_BYTES: usize = 5;
const INVENTORY_LENGTH: usize = 4;
const INVENTORY_SLOT_BYTES: usize = 6;
const INVENTORY_HAS_KEY: u8 = 0x01;
const INVENTORY_HAS_CERTIFICATE: u8 = 0x02;

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
        // GET METADATA F7: P1=01 enumerates ordinary slots. P2 is reserved
        // and must be 00 because inventory has no individual target reference.
        if h.p1 == 0x01 {
            if h.p2 != 0x00 {
                return Err(Sw::WRONG_P1P2);
            }
            // 01 01 01 declares inventory version 1. Tag 02 contains packed
            // six-byte entries; its zero length is patched after enumeration.
            w.output[..INVENTORY_HEADER_BYTES].copy_from_slice(&[
                INVENTORY_VERSION_TAG,
                0x01,
                INVENTORY_VERSION,
                INVENTORY_SLOTS_TAG,
                0x00,
            ]);
            let mut n = INVENTORY_HEADER_BYTES;
            for i in 0..repo::USER_KEY_COUNT {
                let m = repo::meta(i, p)?;
                let cert = match p.storage.size(repo::OBJECTS[i]) {
                    Err(StorageError::Missing) => false,
                    Ok(n) => n > 0,
                    Err(e) => return Err(repo::io(e)),
                };
                let flags = (u8::from(m[repo::ORIGIN] != 0) * INVENTORY_HAS_KEY)
                    | (u8::from(cert) * INVENTORY_HAS_CERTIFICATE);
                // Entry: slot, presence flags (bit 0 key / bit 1 certificate),
                // wire algorithm, origin, PIN policy, touch policy. Certificate-
                // only slots emit zero for the absent key metadata.
                if flags != 0 {
                    w.output[n..n + INVENTORY_SLOT_BYTES].copy_from_slice(&[
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
                    n += INVENTORY_SLOT_BYTES;
                }
            }
            w.output[INVENTORY_LENGTH] = (n - INVENTORY_HEADER_BYTES) as u8;
            self.memory(n);
            return Ok(n as u32);
        }
        // P1=00 queries one reference: P2 selects PIN, PUK, management key
        // or an asymmetric key slot. All other P1 modes are unsupported.
        if h.p1 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        if matches!(h.p2, reference::PIN | reference::PUK) {
            self.pins.ready()?;
            let s = &self.pins.state;
            let (default, limit, remaining) = if h.p2 == reference::PIN {
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
            // TLVs: algorithm FF (PIN/PUK), factory-default flag, then
            // retry limit and remaining attempts (in that order).
            w.output[..10].copy_from_slice(&[
                metadata_tag::ALGORITHM,
                0x01,
                0xff, // PIN/PUK reference, not an asymmetric algorithm.
                metadata_tag::DEFAULT,
                0x01,
                u8::from(default),
                metadata_tag::RETRIES,
                0x02,
                limit,
                remaining,
            ]);
            self.memory(10);
            return Ok(10);
        }
        if h.p2 == reference::MANAGEMENT {
            let mut mgmt = repo::management(p)?;
            // TLVs: AES-192 algorithm, policy (no PIN + configured touch),
            // and whether the management key is still the factory default.
            w.output[..10].copy_from_slice(&[
                metadata_tag::ALGORITHM,
                0x01,
                wire_alg::AES192,
                metadata_tag::POLICY,
                0x02,
                0x00,
                mgmt[repo::MANAGEMENT_TOUCH],
                metadata_tag::DEFAULT,
                0x01,
                u8::from(mgmt[repo::MANAGEMENT_KEY..] == repo::DEFAULT_MGMT),
            ]);
            p.memory.wipe(&mut mgmt);
            self.memory(10);
            return Ok(10);
        }
        let id = repo::slot(h.p2).map_err(|_| Sw::REFERENCE_NOT_FOUND)?;
        let m = repo::meta(id, p)?;
        self.public(id, &m, true, w, p)
    }
    pub(super) fn name(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        // NAME F5: P1=00 reads the label; P1=01 replaces it (management
        // authorization required). P2 identifies the key slot in both modes.
        if h.p1 > 0x01 {
            return Err(Sw::WRONG_P1P2);
        }
        let id = repo::slot(h.p2)?;
        if h.p1 == 0x00 && self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        if h.p1 == 0x01 {
            self.authorized()?;
        }
        let mut m = repo::meta(id, p)?;
        if m[repo::ORIGIN] == 0 {
            return Err(Sw::REFERENCE_NOT_FOUND);
        }
        let n = m[repo::NAME_LENGTH] as usize;
        if h.p1 == 0x00 {
            w.output[..n].copy_from_slice(&m[repo::NAME..repo::NAME + n]);
            self.memory(n);
            return Ok(n as u32);
        }
        let value = &w.input[..self.used];
        if value.len() > repo::NAME_MAX || !value.len().is_multiple_of(2) {
            return Err(Sw::WRONG_DATA);
        }
        // UTF-16LE labels forbid NUL and unpaired surrogates: D800..DBFF
        // starts a pair and must be followed by DC00..DFFF.
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
            for other in 0..repo::KEY_COUNT {
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
        if from == repo::ATTESTATION_KEY {
            return Err(Sw::WRONG_P1P2);
        }
        // MOVE KEY F6: P2 is the source; P1 is the destination, except FF
        // means delete the source. The attestation slot cannot be moved/deleted.
        if h.p1 == 0xff {
            p.storage.remove(repo::KEYS[from]).map_err(repo::io)?;
            return Ok(0);
        }
        let to = repo::slot(h.p1)?;
        if to == repo::ATTESTATION_KEY {
            return Err(Sw::WRONG_P1P2);
        }
        if repo::meta(from, p)?[repo::ORIGIN] == 0 {
            return Err(Sw::REFERENCE_NOT_FOUND);
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
