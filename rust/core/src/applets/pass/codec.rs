// SPDX-License-Identifier: Apache-2.0
//! Fixed RAM slots; persistence stores only headers and actual payloads.
//! No native-layout or previous-format decoding.
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
        if record.len() != 72 || record[0] != 2 {
            return Err(Error::Record);
        }
        let n = usize::from(record[2]);
        let slot = match record[1] {
            1 if n <= 64 => Slot::Oath {
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

/// Stored slot length, checked before slicing or expanding into RAM.
fn stored_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < 4 || bytes[0] != 2 {
        return Err(Error::Record);
    }
    let n = 4 + usize::from(bytes[2]) + if bytes[1] == 1 { 4 } else { 0 };
    if n > 72 || n > bytes.len() {
        return Err(Error::Record);
    }
    Ok(n)
}
pub fn unpack(bytes: &mut [u8; FILE_SIZE], length: usize) -> Result<(), Error> {
    let first = stored_len(&bytes[..length])?;
    let second = stored_len(&bytes[first..length])?;
    if first + second != length {
        return Err(Error::Record);
    }
    bytes.copy_within(first..length, 72);
    bytes[first..72].fill(0);
    bytes[72 + second..].fill(0);
    Layout.decode(&bytes[..72])?;
    Layout.decode(&bytes[72..])?;
    Ok(())
}
pub fn pack(bytes: &[u8; FILE_SIZE], out: &mut [u8; FILE_SIZE]) -> Result<usize, Error> {
    let mut at = 0;
    for record in bytes.chunks_exact(72) {
        Layout.decode(record)?;
        let n = stored_len(record)?;
        out[at..at + n].copy_from_slice(&record[..n]);
        at += n;
    }
    Ok(at)
}
