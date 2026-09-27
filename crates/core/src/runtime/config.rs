// SPDX-License-Identifier: Apache-2.0
//! Native-endian platform page ABI, matching the existing 512-byte config page.
//! The loader owns bytes 0..4. Never include them in the CRC or reset them.
#![forbid(unsafe_code)]
use crate::ports::{StorageError, StoragePort};
pub const INITIALIZED: u32 = 1;
pub const NFC: u32 = 1 << 1;
pub const LED: u32 = 1 << 2;
pub const NDEF: u32 = 1 << 3;
pub const WEBUSB: u32 = 1 << 4;
pub const SERIAL_VALID: u32 = 1 << 5;
pub const PASS: u32 = 1 << 7;
pub const OPENPGP_USB: u32 = 1 << 8;
pub const OPENPGP_NFC: u32 = 1 << 9;
pub const PIV_USB: u32 = 1 << 10;
pub const PIV_NFC: u32 = 1 << 11;
pub const WEBAUTHN: u32 = 1 << 12;
pub const FEATURES: u32 = 0x3f << 7;
pub const ADMIN_FLAGS: u32 = LED | NDEF | WEBUSB | FEATURES;
pub const DEFAULT_FLAGS: u32 = NFC | LED | NDEF | WEBUSB | FEATURES;
const MAGIC: u32 = 0x434b4346;
#[repr(align(4))]
struct Page([u8; 512]);
fn word(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes.try_into().unwrap())
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}
impl Page {
    fn valid(&self) -> bool {
        word(&self.0[4..8]) == MAGIC
            && self.0[8] == 1
            && self.0[9] == 32
            && u16::from_ne_bytes(self.0[10..12].try_into().unwrap()) == 512
            && word(&self.0[508..]) == crc(&self.0[4..508])
    }
    fn seal(&mut self) {
        let sum = crc(&self.0[4..508]);
        self.0[508..].copy_from_slice(&sum.to_ne_bytes());
    }
    fn defaults(&mut self) {
        self.0[4..].fill(0xff);
        self.0[4..8].copy_from_slice(&MAGIC.to_ne_bytes());
        self.0[8..10].copy_from_slice(&[1, 32]);
        self.0[10..12].copy_from_slice(&512u16.to_ne_bytes());
        self.0[12..16].copy_from_slice(&DEFAULT_FLAGS.to_ne_bytes());
        self.0[16..20].fill(0);
        self.0[20..24].copy_from_slice(&[0, 2, 0, 128]);
        self.0[32..288].fill(0);
        self.seal();
    }
    fn commit(&mut self, s: &mut StoragePort<'_>) -> Result<(), StorageError> {
        // Loader state can change independently of the core metadata.
        match s.config_read(0, &mut self.0[..4]) {
            Ok(()) | Err(StorageError::Missing) => (),
            Err(e) => return Err(e),
        }
        self.seal();
        s.config_write(&self.0)
    }
    fn load(&mut self, s: &mut StoragePort<'_>, repair: bool) -> Result<(), StorageError> {
        match s.config_read(0, &mut self.0) {
            Ok(()) => {
                if !self.valid() {
                    if !repair && !self.0[4..].iter().all(|b| *b == 0xff) {
                        return Err(StorageError::Unavailable);
                    }
                    self.defaults();
                }
                Ok(())
            }
            Err(StorageError::Missing) => {
                self.defaults();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
/// No cached permissions: an uncertain write is reloaded by the next caller.
/// The frame ends before applet execution and never spans a crypto operation.
#[inline(never)]
pub fn flags(s: &mut StoragePort<'_>) -> Result<u32, StorageError> {
    let mut page = Page([0xff; 512]);
    page.load(s, false)?;
    Ok(word(&page.0[12..16]))
}
#[inline(never)]
pub fn update(s: &mut StoragePort<'_>, mask: u32, value: u32) -> Result<(), StorageError> {
    let mut page = Page([0xff; 512]);
    page.load(s, true)?;
    let flags = (word(&page.0[12..16]) & !mask) | (value & mask);
    page.0[12..16].copy_from_slice(&flags.to_ne_bytes());
    page.commit(s)
}
pub fn enabled(s: &mut StoragePort<'_>, mask: u32) -> bool {
    flags(s).is_ok_and(|flags| flags & mask != 0)
}

#[cfg(all(test, not(feature = "static-backend")))]
mod tests {
    use super::*;
    use crate::ports::{Record, Storage};
    struct Disk {
        page: [u8; 512],
        read_error: bool,
        write_error: bool,
        writes: usize,
        loader: Option<[u8; 4]>,
    }
    impl Disk {
        fn new() -> Self {
            Self {
                page: [0xff; 512],
                read_error: false,
                write_error: false,
                writes: 0,
                loader: None,
            }
        }
    }
    impl Storage for Disk {
        fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
            unreachable!()
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            unreachable!()
        }
        fn config_read(&mut self, off: usize, out: &mut [u8]) -> Result<(), StorageError> {
            if self.read_error {
                return Err(StorageError::Unavailable);
            }
            if out.len() == 4
                && let Some(loader) = self.loader
            {
                self.page[..4].copy_from_slice(&loader);
            }
            out.copy_from_slice(&self.page[off..off + out.len()]);
            Ok(())
        }
        fn config_write(&mut self, page: &[u8; 512]) -> Result<(), StorageError> {
            assert_eq!(page.as_ptr() as usize % 4, 0);
            self.writes += 1;
            self.page = *page;
            if self.write_error {
                Err(StorageError::Uncertain)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn legacy_crc_defaults_and_selective_update_preserve_all_other_fields() {
        assert_eq!(crc(b"123456789"), 0x340bc6d9);
        let mut disk = Disk::new();
        assert_eq!(flags(&mut disk).unwrap(), 0x1f9e);
        assert_eq!(disk.writes, 0); // Reading unprovisioned data never programs Flash.
        update(&mut disk, NFC, 0).unwrap();
        let mut page = Page(disk.page);
        assert!(page.valid());
        page.0[16..20].copy_from_slice(&[1, 2, 3, 4]);
        page.0[32..288].fill(0x52);
        page.0[288..293].copy_from_slice(&[0x71, 3, 0x18, 0x19, 0x20]);
        page.seal();
        disk.page = page.0;
        let before = disk.page;
        disk.loader = Some([0x12, 0x34, 0x56, 0x78]);
        update(&mut disk, FEATURES, OPENPGP_NFC | PIV_USB).unwrap();
        assert_eq!(&disk.page[..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&disk.page[4..12], &before[4..12]);
        assert_eq!(&disk.page[16..508], &before[16..508]);
        assert_eq!(
            flags(&mut disk).unwrap(),
            LED | NDEF | WEBUSB | OPENPGP_NFC | PIV_USB
        );
        assert!(Page(disk.page).valid());
    }
    #[test]
    fn admin_flags_preserve_initialization_nfc_and_identity() {
        let mut disk = Disk::new();
        write_serial(&mut disk, &[0xa1, 0xb2, 0xc3, 0xd4]).unwrap();
        update(&mut disk, INITIALIZED | NFC, INITIALIZED).unwrap();
        let before = disk.page;
        let selected = LED | WEBUSB | OPENPGP_USB | PIV_USB | WEBAUTHN;
        update(&mut disk, ADMIN_FLAGS, selected).unwrap();
        assert_eq!(flags(&mut disk).unwrap(), selected | INITIALIZED | SERIAL_VALID);
        assert_eq!(serial(&mut disk), [0xa1, 0xb2, 0xc3, 0xd4]);
        assert_eq!(&disk.page[..12], &before[..12]);
        assert_eq!(&disk.page[16..508], &before[16..508]);
        assert!(Page(disk.page).valid());
    }
    #[test]
    fn recovery_preserves_raw_metadata_or_explicitly_erases_it() {
        let mut disk = Disk::new();
        write_serial(&mut disk, &[1, 2, 3, 4]).unwrap();
        disk.page[400] = 0x42; // Preserve even invalid CRC bytes on handoff.
        let original = disk.page;
        recovery(&mut disk, 0xb639a527, false).unwrap();
        assert_eq!(&disk.page[..4], &0xb639a527u32.to_ne_bytes());
        assert_eq!(&disk.page[4..], &original[4..]);
        disk.read_error = true;
        assert!(recovery(&mut disk, 0, false).is_err());
        recovery(&mut disk, 0xb639a527, true).unwrap();
        assert!(disk.page[4..].iter().all(|b| *b == 0xff));
        disk.write_error = true;
        assert!(recovery(&mut disk, 0, true).is_err());
    }
    #[test]
    fn keyboard_table_preserves_identity_and_explicit_zero_usage() {
        let mut disk = Disk::new();
        write_serial(&mut disk, &[1, 2, 3, 4]).unwrap();
        assert_eq!(keyboard_usage(&mut disk, b'A'), Some((2, 4)));
        let mut table = [0; 256];
        table[130..132].copy_from_slice(&[0x40, 0x1d]);
        write_keymap(&mut disk, 17, Some(&table)).unwrap();
        assert_eq!(serial(&mut disk), [1, 2, 3, 4]);
        assert_eq!(&disk.page[20..24], &[17, 2, 0, 128]);
        assert_eq!(keyboard_usage(&mut disk, b'A'), Some((0x40, 0x1d)));
        assert_eq!(keyboard_usage(&mut disk, b'B'), None);
        let mut read = [0; 256];
        assert_eq!(read_keymap(&mut disk, &mut read).unwrap(), 17);
        assert_eq!(read, table);
        write_keymap(&mut disk, 0, None).unwrap();
        assert!(matches!(
            read_keymap(&mut disk, &mut read),
            Err(StorageError::Missing)
        ));
        assert_eq!(keyboard_usage(&mut disk, b'A'), Some((2, 4)));
        assert_eq!(serial(&mut disk), [1, 2, 3, 4]);
    }
    #[test]
    fn identity_matches_legacy_offsets_crc_and_write_once_contract() {
        let mut disk = Disk::new();
        assert_eq!(serial(&mut disk), [0; 4]);
        assert_eq!(disk.writes, 0);
        write_serial(&mut disk, &[0x12, 0x34, 0x56, 0x78]).unwrap();
        assert_eq!(&disk.page[16..20], &[0x12, 0x34, 0x56, 0x78]);
        assert_ne!(word(&disk.page[12..16]) & (1 << 5), 0);
        assert_eq!(serial(&mut disk), [0x12, 0x34, 0x56, 0x78]);
        let writes = disk.writes;
        assert!(write_serial(&mut disk, &[1, 2, 3, 4]).is_err());
        assert_eq!(disk.writes, writes);
        disk.page[0] ^= 1;
        assert_eq!(serial(&mut disk), [0x12, 0x34, 0x56, 0x78]);
        disk.page[16] ^= 1;
        assert_eq!(serial(&mut disk), [0; 4]);
        disk.page[16] ^= 1;
        disk.read_error = true;
        assert_eq!(serial(&mut disk), [0; 4]);
        disk.read_error = false;
        update(&mut disk, SERIAL_VALID, 0).unwrap();
        assert_eq!(serial(&mut disk), [0; 4]);
    }
    #[test]
    fn read_failures_deny_access_and_uncertain_updates_reload_actual_storage() {
        let mut disk = Disk::new();
        disk.read_error = true;
        assert!(!enabled(&mut disk, NFC));
        assert!(update(&mut disk, NFC, 0).is_err());
        assert_eq!(disk.writes, 0);
        disk.read_error = false;
        disk.write_error = true;
        assert!(matches!(
            update(&mut disk, NFC, 0),
            Err(StorageError::Uncertain)
        ));
        assert!(!enabled(&mut disk, NFC));
        disk.page[508] ^= 1; // Torn/uncertain write cannot silently enable defaults.
        assert!(!enabled(&mut disk, NFC));
        assert!(!enabled(&mut disk, WEBAUTHN));
        disk.write_error = false;
        update(&mut disk, NFC, NFC).unwrap();
        assert!(enabled(&mut disk, NFC));
    }
}

/// Factory reset restores user-configurable applet flags, preserving NFC mode,
/// serial, keyboard table and algorithm TLVs exactly as the legacy ADMIN reset.
pub fn reset_admin(s: &mut StoragePort<'_>) -> Result<(), StorageError> {
    let mut present = [0];
    match s.config_read(0, &mut present) {
        Err(StorageError::Missing) => Ok(()), // No page capability in this backend.
        Err(e) => Err(e),
        Ok(()) => update(s, ADMIN_FLAGS, ADMIN_FLAGS),
    }
}

/// Notification only touches disjoint device state after the page borrow ends.
pub fn notify(p: &mut crate::Platform<'_>) {
    let flags = flags(p.storage).unwrap_or(0);
    p.device.configuration_changed(flags);
}

/// Read-only identity access. Invalid/unprovisioned pages return the legacy
/// zero identity; never initialize Flash to answer a serial-number query.
#[inline(never)]
pub fn serial(s: &mut StoragePort<'_>) -> [u8; 4] {
    let mut page = Page([0xff; 512]);
    if page.load(s, false).is_err() || word(&page.0[12..16]) & SERIAL_VALID == 0 {
        return [0; 4];
    }
    page.0[16..20].try_into().unwrap()
}
#[inline(never)]
pub fn write_serial(s: &mut StoragePort<'_>, serial: &[u8; 4]) -> Result<(), StorageError> {
    let mut page = Page([0xff; 512]);
    page.load(s, true)?;
    let flags = word(&page.0[12..16]);
    if flags & SERIAL_VALID != 0 {
        return Err(StorageError::Unavailable);
    }
    page.0[12..16].copy_from_slice(&(flags | SERIAL_VALID).to_ne_bytes());
    page.0[16..20].copy_from_slice(serial);
    page.commit(s)
}

const KEYMAP_VALID: u32 = 1 << 6;
impl Page {
    fn has_keymap(&self) -> bool {
        word(&self.0[12..16]) & KEYMAP_VALID != 0 && self.0[21..24] == [2, 0, 128]
    }
}
/// Keep keyboard settings in the existing page, preserving serial and TLVs.
#[inline(never)]
pub fn write_keymap(
    s: &mut StoragePort<'_>,
    layout: u8,
    table: Option<&[u8; 256]>,
) -> Result<(), StorageError> {
    let mut page = Page([0xff; 512]);
    page.load(s, true)?;
    let mut flags = word(&page.0[12..16]) & !KEYMAP_VALID;
    page.0[20..24].copy_from_slice(&[layout, 2, 0, 128]);
    if let Some(table) = table {
        page.0[32..288].copy_from_slice(table);
        flags |= KEYMAP_VALID;
    } else {
        page.0[32..288].fill(0);
    }
    page.0[12..16].copy_from_slice(&flags.to_ne_bytes());
    page.commit(s)
}
#[inline(never)]
pub fn read_keymap(s: &mut StoragePort<'_>, table: &mut [u8; 256]) -> Result<u8, StorageError> {
    let mut page = Page([0xff; 512]);
    page.load(s, false)?;
    if !page.has_keymap() {
        return Err(StorageError::Missing);
    }
    table.copy_from_slice(&page.0[32..288]);
    Ok(page.0[20])
}
/// A stored zero usage suppresses the character; it never falls back to US.
#[inline(never)]
pub fn keyboard_usage(s: &mut StoragePort<'_>, ch: u8) -> Option<(u8, u8)> {
    let mut page = Page([0xff; 512]);
    if ch < 128 && page.load(s, false).is_ok() && page.has_keymap() {
        let offset = 32 + usize::from(ch) * 2;
        return (page.0[offset + 1] != 0).then_some((page.0[offset], page.0[offset + 1]));
    }
    super::keyboard::ascii(ch)
}

/// Recovery deliberately operates on raw pages, including corrupt metadata.
/// P2=0 preserves every non-loader byte; P2=1 erases metadata as on legacy CIU.
#[inline(never)]
pub fn recovery(s: &mut StoragePort<'_>, word: u32, erase: bool) -> Result<(), StorageError> {
    let mut page = Page([0xff; 512]);
    if !erase {
        s.config_read(0, &mut page.0)?;
    }
    page.0[..4].copy_from_slice(&word.to_ne_bytes());
    s.config_write(&page.0)
}
