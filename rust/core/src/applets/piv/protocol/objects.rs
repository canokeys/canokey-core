// SPDX-License-Identifier: Apache-2.0
//! Object reads and staged PUT transactions. The lifecycle owns commit/abort.
use super::*;

pub(super) struct Put {
    // Object selector only: 5C, one-byte length, then up to three tag bytes.
    // The remaining object content streams to staging storage unchanged.
    prefix: [u8; 5],
    used: usize,
    object: Option<usize>,
    length: usize,
    cap: usize,
    // Retained to recognize the certificate-delete encoding 53 00 at finish.
    first: [u8; 2],
}
impl Put {
    pub(super) const fn new() -> Self {
        Self {
            prefix: [0; 5],
            used: 0,
            object: None,
            length: 0,
            cap: 0,
            first: [0; 2],
        }
    }
    pub(super) fn feed(&mut self, mut b: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        while self.object.is_none() && !b.is_empty() {
            if self.used == 5 {
                return Err(Sw::WRONG_DATA);
            }
            self.prefix[self.used] = b[0];
            self.used += 1;
            b = &b[1..];
            if self.used == 1 && self.prefix[0] != object_tlv::TAG_LIST {
                return Err(Sw::WRONG_DATA);
            }
            if self.used >= 2 {
                let n = self.prefix[1] as usize;
                if !(1..=3).contains(&n) {
                    return Err(Sw::WRONG_LENGTH);
                }
                if self.used == n + 2 {
                    let (tag, _) = codec::tag_list(&self.prefix[..self.used])?;
                    let descriptor = repo::object(tag).ok_or(Sw::FILE_NOT_FOUND)?;
                    self.object = Some(descriptor.index);
                    self.cap = descriptor.capacity_bytes;
                }
            }
        }
        if self.object.is_some() {
            if self.length + b.len() > self.cap {
                return Err(Sw::WRONG_LENGTH);
            }
            for (i, v) in b
                .iter()
                .enumerate()
                .take(2usize.saturating_sub(self.length))
            {
                self.first[self.length + i] = *v;
            }
            p.storage.stage_append(b).map_err(repo::io)?;
            self.length += b.len();
        }
        Ok(())
    }
    pub(super) fn finish(&self, p: &mut Platform<'_>) -> Result<u32, Sw> {
        let i = self.object.ok_or(Sw::WRONG_LENGTH)?;
        // An empty certificate TLV deletes the object; other empty/short
        // objects follow ordinary replace semantics. Never commit a partial PUT.
        if i < repo::KEY_COUNT && self.length == 2 && self.first == [object_tlv::DATA, 0x00] {
            p.storage.stage_abort();
            p.storage.remove(repo::OBJECTS[i]).map_err(repo::io)?;
        } else {
            p.storage.stage_commit(repo::OBJECTS[i]).map_err(repo::io)?;
        }
        Ok(0)
    }
}
impl Piv {
    pub(super) fn get(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        // GET DATA also uses P1/P2=3FFF. The object identifier is carried by
        // the 5C tag list, not by these parameter bytes.
        if h.p1 != object_tlv::SELECT_P1 || h.p2 != object_tlv::SELECT_P2 {
            return Err(Sw::WRONG_P1P2);
        }
        let (tag, n) = codec::tag_list(&w.input[..self.used])?;
        if n != self.used {
            return Err(Sw::WRONG_LENGTH);
        }
        // Discovery is synthesized, not read from flash: it advertises the
        // PIV AID (4F) and PIN usage policy (5F2F) inside template 7E.
        if tag == object_tlv::DISCOVERY {
            let d = [
                0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,
                0x00, 0x5f, 0x2f, 0x02, 0x40, 0x10,
            ];
            w.output[..d.len()].copy_from_slice(&d);
            self.memory(d.len());
            return Ok(d.len() as u32);
        }
        let descriptor = repo::object(tag).ok_or(Sw::FILE_NOT_FOUND)?;
        let i = descriptor.index;
        if descriptor.requires_pin && !self.pins.state.pin_ok {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let n = match p.storage.size(repo::OBJECTS[i]) {
            Err(StorageError::Missing) | Ok(0) => return Err(Sw::FILE_NOT_FOUND),
            Err(e) => return Err(repo::io(e)),
            Ok(n) => n,
        };
        self.response = Response::Object(i);
        self.body_len = n as usize;
        Ok(n)
    }
}
