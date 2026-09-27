// SPDX-License-Identifier: Apache-2.0
//! Fixed RAM slots; persistence stores only headers and actual payloads.
//! No native-layout or previous-format decoding.
#![forbid(unsafe_code)]
use super::domain::{Error, KEY_LENGTH, PASSWORD_LIMIT, Slot, SlotIndex, kind};
pub const SLOT_COUNT: usize = 2;
pub const SLOT_SIZE: usize = 72;
pub const FILE_SIZE: usize = SLOT_COUNT * SLOT_SIZE;
// Offsets below are within one expanded RAM slot. LENGTH counts payload bytes
// (the credential-name bytes for OATH); ENTER controls a trailing Enter key.
// OATH payload is a big-endian 32-bit record ID followed by the credential name.
// Persisted slots omit unused payload capacity; FILE_SIZE is the RAM view size.
const FORMAT_VERSION: u8 = 2;
const VERSION: usize = 0;
const KIND: usize = 1;
const LENGTH: usize = 2;
const ENTER: usize = 3;
const PAYLOAD: usize = 4;
const OATH_ID_BYTES: usize = 4;
const OATH_NAME: usize = PAYLOAD + OATH_ID_BYTES;
const OATH_NAME_LIMIT: usize = 64;
#[derive(Clone, Copy)]
pub struct Layout;
impl Layout {
    fn range(self, index: SlotIndex) -> core::ops::Range<usize> {
        let start = index.get() * SLOT_SIZE;
        start..start + SLOT_SIZE
    }
    pub fn record(self, bytes: &[u8], index: SlotIndex) -> Result<&[u8], Error> {
        bytes.get(self.range(index)).ok_or(Error::Record)
    }
    pub fn record_mut(self, bytes: &mut [u8], index: SlotIndex) -> Result<&mut [u8], Error> {
        bytes.get_mut(self.range(index)).ok_or(Error::Record)
    }
    pub fn decode(self, record: &[u8]) -> Result<Slot<'_>, Error> {
        if record.len() != SLOT_SIZE || record[VERSION] != FORMAT_VERSION {
            return Err(Error::Record);
        }
        let n = usize::from(record[LENGTH]);
        let slot = match record[KIND] {
            kind::OATH if n <= OATH_NAME_LIMIT => Slot::Oath {
                id: u32::from_be_bytes(
                    record[PAYLOAD..OATH_NAME]
                        .try_into()
                        .map_err(|_| Error::Record)?,
                ),
                name: &record[OATH_NAME..OATH_NAME + n],
                enter: record[ENTER],
            },
            kind::OFF if n == 0 && record[ENTER] == 0 => Slot::Off,
            kind::STATIC if n <= PASSWORD_LIMIT => Slot::Static {
                password: &record[PAYLOAD..PAYLOAD + n],
                enter: record[ENTER],
            },
            kind::HMAC if n == KEY_LENGTH && record[ENTER] == 0 => Slot::Hmac(
                record[PAYLOAD..PAYLOAD + KEY_LENGTH]
                    .try_into()
                    .map_err(|_| Error::Record)?,
            ),
            _ => return Err(Error::Record),
        };
        slot.validate()?;
        let used = if record[KIND] == kind::OATH {
            OATH_NAME + n
        } else {
            PAYLOAD + n
        };
        if record[used..].iter().any(|b| *b != 0) {
            return Err(Error::Record);
        }
        Ok(slot)
    }
    pub fn encode_cleared(self, record: &mut [u8], slot: Slot<'_>) -> Result<(), Error> {
        slot.validate()?;
        if record.len() != SLOT_SIZE {
            return Err(Error::Record);
        }
        record.fill(0);
        record[VERSION] = FORMAT_VERSION;
        match slot {
            Slot::Off => (),
            Slot::Oath { id, name, enter } => {
                record[KIND] = kind::OATH;
                record[LENGTH] = name.len() as u8;
                record[ENTER] = enter;
                record[PAYLOAD..OATH_NAME].copy_from_slice(&id.to_be_bytes());
                record[OATH_NAME..OATH_NAME + name.len()].copy_from_slice(name);
            }
            Slot::Static { password, enter } => {
                record[KIND] = kind::STATIC;
                record[LENGTH] = password.len() as u8;
                record[ENTER] = enter;
                record[PAYLOAD..PAYLOAD + password.len()].copy_from_slice(password);
            }
            Slot::Hmac(key) => {
                record[KIND] = kind::HMAC;
                record[LENGTH] = KEY_LENGTH as u8;
                record[PAYLOAD..PAYLOAD + KEY_LENGTH].copy_from_slice(key);
            }
        }
        Ok(())
    }
}

/// Stored slot length, checked before slicing or expanding into RAM.
fn stored_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < PAYLOAD || bytes[VERSION] != FORMAT_VERSION {
        return Err(Error::Record);
    }
    let n = PAYLOAD
        + usize::from(bytes[LENGTH])
        + if bytes[KIND] == kind::OATH {
            OATH_ID_BYTES
        } else {
            0
        };
    if n > SLOT_SIZE || n > bytes.len() {
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
    bytes.copy_within(first..length, SLOT_SIZE);
    bytes[first..SLOT_SIZE].fill(0);
    bytes[SLOT_SIZE + second..].fill(0);
    Layout.decode(&bytes[..SLOT_SIZE])?;
    Layout.decode(&bytes[SLOT_SIZE..])?;
    Ok(())
}
pub fn pack(bytes: &[u8; FILE_SIZE], out: &mut [u8; FILE_SIZE]) -> Result<usize, Error> {
    let mut at = 0;
    let (records, _) = bytes.as_chunks::<SLOT_SIZE>();
    for record in records {
        Layout.decode(record)?;
        let n = stored_len(record)?;
        out[at..at + n].copy_from_slice(&record[..n]);
        at += n;
    }
    Ok(at)
}
