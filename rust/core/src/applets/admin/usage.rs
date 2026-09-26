// SPDX-License-Identifier: Apache-2.0
//! ADMIN usage attribution over the durable Rust record namespace.
#![forbid(unsafe_code)]
use crate::ports::{Record, StorageError, StoragePort};
use canokey_protocol::response::StatusWord as Sw;
pub fn read(storage: &mut StoragePort<'_>, applets: bool, out: &mut [u8]) -> Result<usize, Sw> {
    let (used, total) = storage.usage().map_err(|_| Sw::UNABLE_TO_PROCESS)?;
    if used > total {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    if !applets {
        out[..2].copy_from_slice(&[(used / 1024) as u8, (total / 1024) as u8]);
        return Ok(2);
    }
    out[..48].fill(0);
    for slot in 0..7 {
        out[slot * 6] = (slot + 1) as u8;
    }
    let mut attributed = 0u32;
    for id in 0..=185 {
        let applet = match id {
            0 => 7,
            1 => 1,
            2..=3 => 4,
            4..=13 => 2,
            14..=76 => 3,
            77..=183 => 5,
            _ => 6,
        };
        let offset = (applet - 1) * 6;
        match storage.size(Record::from_id(id).unwrap()) {
            Ok(size) => {
                let bytes = u32::from_be_bytes(out[offset + 2..offset + 6].try_into().unwrap());
                out[offset + 2..offset + 6]
                    .copy_from_slice(&bytes.saturating_add(size).to_be_bytes());
                attributed = attributed.saturating_add(size);
            }
            Err(StorageError::Missing) => out[offset + 1] |= 1,
            Err(_) => return Err(Sw::UNABLE_TO_PROCESS),
        }
    }
    out[44..48].copy_from_slice(&used.saturating_sub(attributed).to_be_bytes());
    Ok(48)
}

#[cfg(all(test, not(feature = "static-backend")))]
mod tests {
    use super::*;
    use crate::ports::Storage;
    struct Disk {
        error: bool,
        physical: u32,
        piv_extra: u32,
    }
    impl Storage for Disk {
        fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
            unreachable!()
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            unreachable!()
        }
        fn usage(&mut self) -> Result<(u32, u32), StorageError> {
            Ok((self.physical, 131072))
        }
        fn size(&mut self, r: Record) -> Result<u32, StorageError> {
            if self.error && r.id() == 180 {
                return Err(StorageError::Unavailable);
            }
            match r.id() {
                0 => Ok(7),
                1 => Ok(1),
                2 => Ok(4),
                13 => Ok(2),
                76 => Ok(3 + self.piv_extra),
                180 => Ok(5),
                185 => Ok(6),
                _ => Err(StorageError::Missing),
            }
        }
    }
    #[test]
    fn groups_use_big_endian_bytes_and_system_overhead() {
        let mut disk = Disk {
            error: false,
            physical: 4124,
            piv_extra: 0,
        };
        let mut out = [0; 48];
        assert_eq!(read(&mut disk, false, &mut out), Ok(2));
        assert_eq!(&out[..2], &[4, 128]);
        assert_eq!(read(&mut disk, true, &mut out), Ok(48));
        for i in 0..7 {
            let id = (i + 1) as u8;
            assert_eq!(
                &out[i * 6..i * 6 + 6],
                &[id, if id == 1 || id == 7 { 0 } else { 1 }, 0, 0, 0, id]
            );
        }
        assert_eq!(&out[42..], &[0, 0, 0, 0, 0x10, 0]);
        // Added PIV records affect only PIV attribution, not system overhead.
        let before = out;
        disk.piv_extra = 7;
        disk.physical += 7;
        read(&mut disk, true, &mut out).unwrap();
        assert_eq!(&out[..12], &before[..12]);
        assert_eq!(&out[12..18], &[3, 1, 0, 0, 0, 10]);
        assert_eq!(&out[18..], &before[18..]);
        disk.physical = 1;
        read(&mut disk, true, &mut out).unwrap();
        assert_eq!(&out[44..], &[0; 4]);
        disk.error = true;
        assert_eq!(read(&mut disk, true, &mut out), Err(Sw::UNABLE_TO_PROCESS));
        disk.error = false;
        disk.physical = 131073;
        assert_eq!(read(&mut disk, false, &mut out), Err(Sw::UNABLE_TO_PROCESS));
    }
}
