// SPDX-License-Identifier: Apache-2.0
//! Version 2 slot: version/kind/length/enter plus 68 bytes; v1 input remains readable.
//! Independent of C enum width, host endianness and legacy PASS files.
#![forbid(unsafe_code)]
use super::domain::{Error, Slot, SlotIndex};
pub const FILE_SIZE: usize = 144;
#[derive(Clone, Copy)]
pub struct Layout;
impl Layout {
    fn range(self, index: SlotIndex) -> core::ops::Range<usize> {
        let start = index.get() * 72;
        start..start + 72
    }
    pub fn record(self, bytes: &[u8], index: SlotIndex) -> Result<&[u8], Error> {
        bytes.get(self.range(index)).ok_or(Error::Record)
    }
    pub fn record_mut(self, bytes: &mut [u8], index: SlotIndex) -> Result<&mut [u8], Error> {
        bytes.get_mut(self.range(index)).ok_or(Error::Record)
    }
    pub fn decode(self, record: &[u8]) -> Result<Slot<'_>, Error> {
        if !((record.len() == 36 && record[0] == 1) || (record.len() == 72 && record[0] == 2)) {
            return Err(Error::Record);
        }
        let n = usize::from(record[2]);
        let slot = match record[1] {
            1 if record.len() == 72 && n <= 64 => Slot::Oath {
                id: u32::from_be_bytes(record[4..8].try_into().map_err(|_| Error::Record)?),
                name: &record[8..8 + n],
                enter: record[3],
            },
            0 if n == 0 && record[3] == 0 => Slot::Off,
            2 if n <= 32 => Slot::Static {
                password: &record[4..4 + n],
                enter: record[3],
            },
            3 if n == 20 && record[3] == 0 => {
                Slot::Hmac(record[4..24].try_into().map_err(|_| Error::Record)?)
            }
            _ => return Err(Error::Record),
        };
        slot.validate()?;
        let used = if record[1] == 1 { 8 + n } else { 4 + n };
        if record[used..].iter().any(|b| *b != 0) {
            return Err(Error::Record);
        }
        Ok(slot)
    }
    pub fn encode_cleared(self, record: &mut [u8], slot: Slot<'_>) -> Result<(), Error> {
        slot.validate()?;
        if record.len() != 72 {
            return Err(Error::Record);
        }
        record.fill(0);
        record[0] = 2;
        match slot {
            Slot::Off => (),
            Slot::Oath { id, name, enter } => {
                record[1] = 1;
                record[2] = name.len() as u8;
                record[3] = enter;
                record[4..8].copy_from_slice(&id.to_be_bytes());
                record[8..8 + name.len()].copy_from_slice(name);
            }
            Slot::Static { password, enter } => {
                record[1] = 2;
                record[2] = password.len() as u8;
                record[3] = enter;
                record[4..4 + password.len()].copy_from_slice(password);
            }
            Slot::Hmac(key) => {
                record[1] = 3;
                record[2] = 20;
                record[4..24].copy_from_slice(key);
            }
        }
        Ok(())
    }
}
