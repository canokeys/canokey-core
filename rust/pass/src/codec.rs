// SPDX-License-Identifier: Apache-2.0
//! Existing packed C record format. Enum width and native endianness belong
//! here, not in the slot rules. CIU remains two 71-byte slots (142 bytes).
#![forbid(unsafe_code)]
use crate::domain::{Error, KEY_LENGTH, NAME_LIMIT, PASSWORD_LIMIT, Slot, SlotIndex};

#[derive(Clone, Copy)]
pub struct Layout {
    type_width: usize,
}
impl Layout {
    pub fn new(type_width: u8) -> Result<Self, Error> {
        match type_width {
            1 | 4 => Ok(Self {
                type_width: usize::from(type_width),
            }),
            _ => Err(Error::Record),
        }
    }
    pub fn slot_size(self) -> usize {
        self.type_width + 70
    }
    pub fn file_size(self) -> usize {
        2 * self.slot_size()
    }
    fn range(self, index: SlotIndex) -> core::ops::Range<usize> {
        let start = index.get() * self.slot_size();
        start..start + self.slot_size()
    }
    pub fn record(self, bytes: &[u8], index: SlotIndex) -> Result<&[u8], Error> {
        bytes.get(self.range(index)).ok_or(Error::Record)
    }
    pub fn record_mut(self, bytes: &mut [u8], index: SlotIndex) -> Result<&mut [u8], Error> {
        bytes.get_mut(self.range(index)).ok_or(Error::Record)
    }
    pub fn decode(self, record: &[u8]) -> Result<Slot<'_>, Error> {
        if record.len() != self.slot_size() {
            return Err(Error::Record);
        }
        let kind = if self.type_width == 1 {
            u32::from(record[0])
        } else {
            u32::from_ne_bytes(record[..4].try_into().map_err(|_| Error::Record)?)
        };
        let body = &record[self.type_width..];
        let enter = body[69];
        Ok(match kind {
            0 => Slot::Off,
            1 => {
                let n = usize::from(body[4]);
                if n > NAME_LIMIT {
                    return Err(Error::Record);
                }
                Slot::Oath {
                    offset: u32::from_ne_bytes(body[..4].try_into().map_err(|_| Error::Record)?),
                    name: &body[5..5 + n],
                    enter,
                }
            }
            2 => {
                let n = usize::from(body[0]);
                if n > PASSWORD_LIMIT {
                    return Err(Error::Record);
                }
                Slot::Static {
                    password: &body[1..1 + n],
                    enter,
                }
            }
            3 => Slot::Hmac(body[..KEY_LENGTH].try_into().map_err(|_| Error::Record)?),
            value => Slot::Unknown(value),
        })
    }
    /// Caller securely wipes the record before encoding to clear inactive union
    /// bytes and secrets. Do not serialize the memory representation of Slot.
    pub fn encode_cleared(self, record: &mut [u8], slot: Slot<'_>) -> Result<(), Error> {
        slot.validate()?;
        if record.len() != self.slot_size() {
            return Err(Error::Record);
        }
        let kind: u32 = match slot {
            Slot::Off => 0,
            Slot::Oath { .. } => 1,
            Slot::Static { .. } => 2,
            Slot::Hmac(_) => 3,
            Slot::Unknown(_) => return Err(Error::Kind),
        };
        if self.type_width == 1 {
            record[0] = kind as u8;
        } else {
            record[..4].copy_from_slice(&kind.to_ne_bytes());
        }
        let body = &mut record[self.type_width..];
        match slot {
            Slot::Static { password, enter } => {
                body[0] = password.len() as u8;
                body[1..1 + password.len()].copy_from_slice(password);
                body[69] = enter;
            }
            Slot::Oath {
                offset,
                name,
                enter,
            } => {
                body[..4].copy_from_slice(&offset.to_ne_bytes());
                body[4] = name.len() as u8;
                body[5..5 + name.len()].copy_from_slice(name);
                body[69] = enter;
            }
            Slot::Hmac(key) => body[..KEY_LENGTH].copy_from_slice(key),
            _ => (),
        }
        Ok(())
    }
}
