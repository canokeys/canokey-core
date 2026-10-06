// SPDX-License-Identifier: Apache-2.0
//! ADMIN usage attribution over the durable Rust record namespace.
#![forbid(unsafe_code)]
use crate::ports::{Record, StorageError, StoragePort};
use canokey_protocol::response::StatusWord as Sw;
const BYTES_PER_KIB: u32 = 1024;
pub(super) const SUMMARY_BYTES: usize = 2;
// INS 0x41/P1 0x01 returns eight entries: applets 1..=7, then system ID 0.
// Each entry is [ID, missing-record flags, logical bytes as big-endian u32].
const ENTRY_BYTES: usize = 6;
const FLAGS_OFFSET: usize = 1;
const SIZE_OFFSET: usize = 2;
const MISSING_RECORD: u8 = 0x01;
const ADMIN: usize = 1;
const OPENPGP: usize = 2;
const PIV: usize = 3;
const OATH: usize = 4;
const CTAP: usize = 5;
const NDEF: usize = 6;
const PASS: usize = 7;
const APPLET_COUNT: usize = 7;
const SYSTEM_OFFSET: usize = APPLET_COUNT * ENTRY_BYTES;
pub(super) const APPLET_BYTES: usize = SYSTEM_OFFSET + ENTRY_BYTES;

fn applet_id(record: Record) -> usize {
    // Include reserved CTAP IDs in its namespace; absent files set the flag.
    let id = record.id();
    if id == Record::Pass.id() {
        PASS
    } else if id == Record::AdminPin.id() {
        ADMIN
    } else if id < Record::PgpState.id() {
        OATH
    } else if id < Record::PivState.id() {
        OPENPGP
    } else if id < Record::CtapPin.id() {
        PIV
    } else if id < Record::NdefCapability.id() {
        CTAP
    } else {
        NDEF
    }
}

pub fn read(storage: &mut StoragePort<'_>, applets: bool, out: &mut [u8]) -> Result<usize, Sw> {
    let (used, total) = storage.usage().map_err(|_| Sw::UNABLE_TO_PROCESS)?;
    if used > total {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    if !applets {
        out[..SUMMARY_BYTES]
            .copy_from_slice(&[(used / BYTES_PER_KIB) as u8, (total / BYTES_PER_KIB) as u8]);
        return Ok(SUMMARY_BYTES);
    }
    out[..APPLET_BYTES].fill(0);
    for slot in 0..APPLET_COUNT {
        out[slot * ENTRY_BYTES] = (slot + 1) as u8;
    }
    let mut attributed = 0u32;
    for id in Record::Pass.id()..=Record::NdefMessage.id() {
        let record = Record::from_id(id).unwrap();
        let offset = (applet_id(record) - 1) * ENTRY_BYTES;
        let size_range = offset + SIZE_OFFSET..offset + ENTRY_BYTES;
        match storage.size(record) {
            Ok(size) => {
                let bytes = u32::from_be_bytes(out[size_range.clone()].try_into().unwrap());
                out[size_range].copy_from_slice(&bytes.saturating_add(size).to_be_bytes());
                attributed = attributed.saturating_add(size);
            }
            Err(StorageError::Missing) => out[offset + FLAGS_OFFSET] |= MISSING_RECORD,
            Err(_) => return Err(Sw::UNABLE_TO_PROCESS),
        }
    }
    // Physical allocation includes metadata/page slack that record lengths omit.
    out[SYSTEM_OFFSET + SIZE_OFFSET..APPLET_BYTES]
        .copy_from_slice(&used.saturating_sub(attributed).to_be_bytes());
    Ok(APPLET_BYTES)
}

#[cfg(all(test, not(feature = "static-backend")))]
mod tests {
    use super::*;
    use crate::ports::Storage;
    const TOTAL_BYTES: u32 = 128 * BYTES_PER_KIB;
    const OVERHEAD_BYTES: u32 = 4 * BYTES_PER_KIB;
    // One record per applet, sized to its response ID (sum 1..=7 is 28).
    const ATTRIBUTED_BYTES: u32 = (APPLET_COUNT * (APPLET_COUNT + 1) / 2) as u32;
    const PIV_GROWTH_BYTES: u32 = 7;
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
            Ok((self.physical, TOTAL_BYTES))
        }
        fn size(&mut self, r: Record) -> Result<u32, StorageError> {
            if self.error && r == Record::CtapLargeBlob {
                return Err(StorageError::Unavailable);
            }
            match r {
                Record::Pass => Ok(PASS as u32),
                Record::AdminPin => Ok(ADMIN as u32),
                Record::OathMetadata => Ok(OATH as u32),
                Record::PgpCertAut => Ok(OPENPGP as u32),
                Record::PivProvision => Ok(PIV as u32 + self.piv_extra),
                Record::CtapLargeBlob => Ok(CTAP as u32),
                Record::NdefMessage => Ok(NDEF as u32),
                _ => Err(StorageError::Missing),
            }
        }
    }
    #[test]
    fn groups_use_big_endian_bytes_and_system_overhead() {
        let mut disk = Disk {
            error: false,
            physical: OVERHEAD_BYTES + ATTRIBUTED_BYTES,
            piv_extra: 0,
        };
        let mut out = [0; APPLET_BYTES];
        assert_eq!(read(&mut disk, false, &mut out), Ok(2));
        // Summary rounds away the 28 logical bytes above the 4 KiB overhead.
        assert_eq!(&out[..SUMMARY_BYTES], &[4, 128]);
        assert_eq!(read(&mut disk, true, &mut out), Ok(48));
        for i in 0..APPLET_COUNT {
            let id = (i + 1) as u8;
            assert_eq!(
                &out[i * ENTRY_BYTES..(i + 1) * ENTRY_BYTES],
                &[id, if id == 1 || id == 7 { 0 } else { 1 }, 0, 0, 0, id]
            );
        }
        // System ID/flags are zero; 4096 bytes is encoded as 0x00001000.
        assert_eq!(&out[SYSTEM_OFFSET..], &[0, 0, 0, 0, 0x10, 0]);
        // Added PIV records affect only PIV attribution, not system overhead.
        let before = out;
        disk.piv_extra = PIV_GROWTH_BYTES;
        disk.physical += PIV_GROWTH_BYTES;
        read(&mut disk, true, &mut out).unwrap();
        let piv_offset = (PIV - 1) * ENTRY_BYTES;
        let piv_end = piv_offset + ENTRY_BYTES;
        assert_eq!(&out[..piv_offset], &before[..piv_offset]);
        assert_eq!(&out[piv_offset..piv_end], &[3, 1, 0, 0, 0, 10]);
        assert_eq!(&out[piv_end..], &before[piv_end..]);
        disk.physical = 1;
        read(&mut disk, true, &mut out).unwrap();
        assert_eq!(
            &out[SYSTEM_OFFSET + SIZE_OFFSET..],
            &[0; core::mem::size_of::<u32>()]
        );
        disk.error = true;
        assert_eq!(read(&mut disk, true, &mut out), Err(Sw::UNABLE_TO_PROCESS));
        disk.error = false;
        disk.physical = TOTAL_BYTES + 1;
        assert_eq!(read(&mut disk, false, &mut out), Err(Sw::UNABLE_TO_PROCESS));
    }
}
