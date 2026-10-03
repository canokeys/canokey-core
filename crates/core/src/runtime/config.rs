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
pub const FEATURE_SHIFT: u32 = 7;
pub const FEATURE_MASK: u8 = 0x3f;
pub const FEATURES: u32 = (FEATURE_MASK as u32) << FEATURE_SHIFT;
pub const ADMIN_FLAGS: u32 = LED | NDEF | WEBUSB | FEATURES;
pub const DEFAULT_FLAGS: u32 = NFC | LED | NDEF | WEBUSB | FEATURES;
// Native-endian config ABI: loader[4], CKCF magic, version/header length,
// page length, flags, serial, keymap header; table at 32; CRC at page end.
const MAGIC: u32 = 0x434b4346; // ASCII "CKCF", stored in native endian.
const CRC_POLYNOMIAL: u32 = 0xedb8_8320; // Reflected CRC-32/ISO-HDLC, no final XOR.
const PAGE_BYTES: usize = 512;
const MAGIC_OFFSET: usize = 4;
const VERSION_OFFSET: usize = 8;
const HEADER_LENGTH_OFFSET: usize = 9;
const PAGE_LENGTH_OFFSET: usize = 10;
const FLAGS_OFFSET: usize = 12;
const SERIAL_OFFSET: usize = 16;
pub const SERIAL_BYTES: usize = 4;
const KEYMAP_HEADER_OFFSET: usize = 20;
const KEYMAP_HEADER_END: usize = 24;
const KEYMAP_OFFSET: usize = 32;
const CRC_OFFSET: usize = PAGE_BYTES - core::mem::size_of::<u32>();
const FORMAT_VERSION: u8 = 0x01;
const HEADER_BYTES: u8 = 0x20;
const KEYMAP_ENTRY_BYTES: usize = 2;
const KEYMAP_ENTRY_COUNT: usize = 128;
pub const KEYMAP_BYTES: usize = KEYMAP_ENTRY_COUNT * KEYMAP_ENTRY_BYTES;
const KEYMAP_END: usize = KEYMAP_OFFSET + KEYMAP_BYTES;
// layout=US, entry width2, first ASCII0, count128.
const DEFAULT_KEYMAP_HEADER: [u8; 4] = [0x00, 0x02, 0x00, 0x80];
fn keymap_header(layout: u8) -> [u8; 4] {
    let mut header = DEFAULT_KEYMAP_HEADER;
    header[0] = layout;
    header
}
#[repr(align(4))]
struct Page([u8; PAGE_BYTES]);
fn word(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes.try_into().unwrap())
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (CRC_POLYNOMIAL & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}
impl Page {
    #[inline(always)]
    fn with_page<T>(
        s: &mut StoragePort<'_>,
        repair: bool,
        run: impl FnOnce(&mut Self, &mut StoragePort<'_>, bool) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let mut page = Self([0xff; PAGE_BYTES]);
        let persisted = page.load(s, repair)?;
        run(&mut page, s, persisted)
    }
    fn flags(&self) -> u32 {
        word(&self.0[FLAGS_OFFSET..SERIAL_OFFSET])
    }
    fn valid(&self) -> bool {
        word(&self.0[MAGIC_OFFSET..VERSION_OFFSET]) == MAGIC
            && self.0[VERSION_OFFSET] == FORMAT_VERSION
            && self.0[HEADER_LENGTH_OFFSET] == HEADER_BYTES
            && u16::from_ne_bytes(self.0[PAGE_LENGTH_OFFSET..FLAGS_OFFSET].try_into().unwrap())
                == PAGE_BYTES as u16
            && word(&self.0[CRC_OFFSET..]) == crc(&self.0[MAGIC_OFFSET..CRC_OFFSET])
    }
    fn seal(&mut self) {
        let sum = crc(&self.0[MAGIC_OFFSET..CRC_OFFSET]);
        self.0[CRC_OFFSET..].copy_from_slice(&sum.to_ne_bytes());
    }
    fn defaults(&mut self) {
        self.0[MAGIC_OFFSET..].fill(0xff);
        self.0[MAGIC_OFFSET..VERSION_OFFSET].copy_from_slice(&MAGIC.to_ne_bytes());
        self.0[VERSION_OFFSET..PAGE_LENGTH_OFFSET].copy_from_slice(&[FORMAT_VERSION, HEADER_BYTES]);
        self.0[PAGE_LENGTH_OFFSET..FLAGS_OFFSET]
            .copy_from_slice(&(PAGE_BYTES as u16).to_ne_bytes());
        self.0[FLAGS_OFFSET..SERIAL_OFFSET].copy_from_slice(&DEFAULT_FLAGS.to_ne_bytes());
        self.0[SERIAL_OFFSET..KEYMAP_HEADER_OFFSET].fill(0);
        self.0[KEYMAP_HEADER_OFFSET..KEYMAP_HEADER_END].copy_from_slice(&DEFAULT_KEYMAP_HEADER);
        self.0[KEYMAP_OFFSET..KEYMAP_END].fill(0);
        // Read-only defaults need no checksum; commit seals after all edits.
    }
    fn commit(&mut self, s: &mut StoragePort<'_>) -> Result<(), StorageError> {
        // Loader state can change independently of the core metadata.
        match s.config_read(0, &mut self.0[..MAGIC_OFFSET]) {
            Ok(()) | Err(StorageError::Missing) => (),
            Err(e) => return Err(e),
        }
        self.seal();
        s.config_write(&self.0)
    }
    // True means the page was already valid on storage, not synthesized defaults.
    fn load(&mut self, s: &mut StoragePort<'_>, repair: bool) -> Result<bool, StorageError> {
        match s.config_read(0, &mut self.0) {
            Ok(()) => {
                if !self.valid() {
                    if !repair && !self.0[MAGIC_OFFSET..].iter().all(|b| *b == 0xff) {
                        return Err(StorageError::Unavailable);
                    }
                    self.defaults();
                    return Ok(false);
                }
                Ok(true)
            }
            Err(StorageError::Missing) => {
                self.defaults();
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}
/// No cached permissions: an uncertain write is reloaded by the next caller.
/// The frame ends before applet execution and never spans a crypto operation.
#[inline(never)]
pub fn flags(s: &mut StoragePort<'_>) -> Result<u32, StorageError> {
    Page::with_page(s, false, |page, _, _| Ok(page.flags()))
}
#[inline(never)]
pub fn update(s: &mut StoragePort<'_>, mask: u32, value: u32) -> Result<(), StorageError> {
    Page::with_page(s, true, |page, s, persisted| {
        let old = page.flags();
        let flags = (old & !mask) | (value & mask);
        if persisted && flags == old {
            return Ok(());
        }
        page.0[FLAGS_OFFSET..SERIAL_OFFSET].copy_from_slice(&flags.to_ne_bytes());
        page.commit(s)
    })
}
pub fn enabled(s: &mut StoragePort<'_>, mask: u32) -> bool {
    flags(s).is_ok_and(|flags| flags & mask != 0)
}

#[cfg(all(test, not(feature = "static-backend")))]
mod tests {
    use super::*;
    use crate::ports::{Record, Storage};
    struct Disk {
        page: [u8; PAGE_BYTES],
        read_error: bool,
        write_error: bool,
        writes: usize,
        loader: Option<[u8; 4]>,
    }
    impl Disk {
        fn new() -> Self {
            Self {
                page: [0xff; PAGE_BYTES],
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
                self.page[..MAGIC_OFFSET].copy_from_slice(&loader);
            }
            out.copy_from_slice(&self.page[off..off + out.len()]);
            Ok(())
        }
        fn config_write(&mut self, page: &[u8; PAGE_BYTES]) -> Result<(), StorageError> {
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
    fn identical_updates_skip_writes_but_defaults_and_repairs_are_persisted() {
        let mut disk = Disk::new();
        update(&mut disk, LED, LED).unwrap();
        assert_eq!(disk.writes, 1, "erased pages must receive defaults");
        disk.write_error = true;
        update(&mut disk, LED, LED).unwrap();
        assert_eq!(disk.writes, 1);
        disk.write_error = false;
        disk.page[508] ^= 1;
        update(&mut disk, LED, LED).unwrap();
        assert_eq!(disk.writes, 2, "repair cannot be skipped");
        assert!(Page(disk.page).valid());
        write_keymap(&mut disk, 0, None).unwrap();
        assert_eq!(disk.writes, 2);
        let table = [7; 256];
        write_keymap(&mut disk, 17, Some(&table)).unwrap();
        assert_eq!(disk.writes, 3);
        write_keymap(&mut disk, 17, Some(&table)).unwrap();
        assert_eq!(disk.writes, 3);
        disk.page[508] ^= 1;
        write_keymap(&mut disk, 0, None).unwrap();
        assert_eq!(disk.writes, 4);
        assert!(Page(disk.page).valid());
        disk.read_error = true;
        assert!(update(&mut disk, LED, LED).is_err());
        assert!(write_keymap(&mut disk, 0, None).is_err());
    }
    #[test]
    fn keymap_skip_requires_matching_flags_and_header() {
        let mut disk = Disk::new();
        let table = [0; 256];
        write_keymap(&mut disk, 17, Some(&table)).unwrap();
        let canonical = disk.page;
        for offset in [20, 21, 22, 23] {
            let mut page = Page(canonical);
            page.0[offset] ^= 1;
            page.seal();
            disk.page = page.0;
            let writes = disk.writes;
            write_keymap(&mut disk, 17, Some(&table)).unwrap();
            assert_eq!(disk.writes, writes + 1);
            assert_eq!(disk.page, canonical);
        }
        let mut page = Page(canonical);
        let flags = word(&page.0[FLAGS_OFFSET..SERIAL_OFFSET]) & !KEYMAP_VALID;
        page.0[FLAGS_OFFSET..SERIAL_OFFSET].copy_from_slice(&flags.to_ne_bytes());
        page.seal();
        disk.page = page.0;
        let writes = disk.writes;
        write_keymap(&mut disk, 17, Some(&table)).unwrap();
        assert_eq!(disk.writes, writes + 1);
        assert_eq!(disk.page, canonical);
        // A zero-valued custom map still differs from no custom map.
        write_keymap(&mut disk, 17, None).unwrap();
        assert_eq!(disk.writes, writes + 2);
        assert_eq!(
            word(&disk.page[FLAGS_OFFSET..SERIAL_OFFSET]) & KEYMAP_VALID,
            0
        );
        write_keymap(&mut disk, 17, None).unwrap();
        assert_eq!(disk.writes, writes + 2);
        // Disabled but stale bytes must be cleared, even with a valid CRC.
        let mut page = Page(disk.page);
        page.0[32] = 1;
        page.seal();
        disk.page = page.0;
        write_keymap(&mut disk, 17, None).unwrap();
        assert_eq!(disk.writes, writes + 3);
        assert!(disk.page[KEYMAP_OFFSET..KEYMAP_END].iter().all(|&b| b == 0));
        assert!(Page(disk.page).valid());
    }
    #[test]
    fn legacy_crc_defaults_and_selective_update_preserve_all_other_fields() {
        assert_eq!(crc(b"123456789"), 0x340bc6d9);
        let mut disk = Disk::new();
        assert_eq!(flags(&mut disk).unwrap(), DEFAULT_FLAGS);
        assert_eq!(disk.writes, 0); // Reading unprovisioned data never programs Flash.
        update(&mut disk, NFC, 0).unwrap();
        let mut page = Page(disk.page);
        assert!(page.valid());
        page.0[SERIAL_OFFSET..KEYMAP_HEADER_OFFSET].copy_from_slice(&[1, 2, 3, 4]);
        page.0[KEYMAP_OFFSET..KEYMAP_END].fill(0x52);
        page.0[288..293].copy_from_slice(&[0x71, 3, 0x18, 0x19, 0x20]);
        page.seal();
        disk.page = page.0;
        let before = disk.page;
        disk.loader = Some([0x12, 0x34, 0x56, 0x78]);
        update(&mut disk, FEATURES, OPENPGP_NFC | PIV_USB).unwrap();
        assert_eq!(&disk.page[..MAGIC_OFFSET], &[0x12, 0x34, 0x56, 0x78]);
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
        assert_eq!(
            flags(&mut disk).unwrap(),
            selected | INITIALIZED | SERIAL_VALID
        );
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
        assert_eq!(&disk.page[..MAGIC_OFFSET], &0xb639a527u32.to_ne_bytes());
        assert_eq!(&disk.page[MAGIC_OFFSET..], &original[MAGIC_OFFSET..]);
        disk.read_error = true;
        assert!(recovery(&mut disk, 0, false).is_err());
        recovery(&mut disk, 0xb639a527, true).unwrap();
        assert!(disk.page[MAGIC_OFFSET..].iter().all(|b| *b == 0xff));
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
        assert_eq!(
            &disk.page[KEYMAP_HEADER_OFFSET..KEYMAP_HEADER_END],
            &[17, 2, 0, 128]
        );
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
        assert_eq!(
            &disk.page[SERIAL_OFFSET..KEYMAP_HEADER_OFFSET],
            &[0x12, 0x34, 0x56, 0x78]
        );
        assert_ne!(word(&disk.page[FLAGS_OFFSET..SERIAL_OFFSET]) & (1 << 5), 0);
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
    Page::with_page(s, false, |page, _, _| {
        if page.flags() & SERIAL_VALID == 0 {
            return Ok([0; 4]);
        }
        Ok(page.0[SERIAL_OFFSET..KEYMAP_HEADER_OFFSET]
            .try_into()
            .unwrap())
    })
    .unwrap_or([0; 4])
}
#[inline(never)]
pub fn write_serial(s: &mut StoragePort<'_>, serial: &[u8; 4]) -> Result<(), StorageError> {
    Page::with_page(s, true, |page, s, _| {
        let flags = page.flags();
        if flags & SERIAL_VALID != 0 {
            return Err(StorageError::Unavailable);
        }
        page.0[FLAGS_OFFSET..SERIAL_OFFSET].copy_from_slice(&(flags | SERIAL_VALID).to_ne_bytes());
        page.0[SERIAL_OFFSET..KEYMAP_HEADER_OFFSET].copy_from_slice(serial);
        page.commit(s)
    })
}

const KEYMAP_VALID: u32 = 1 << 6;
impl Page {
    fn has_keymap(&self) -> bool {
        self.flags() & KEYMAP_VALID != 0
            && self.0[KEYMAP_HEADER_OFFSET + 1..KEYMAP_HEADER_END] == DEFAULT_KEYMAP_HEADER[1..]
    }
}
/// Keep keyboard settings in the existing page, preserving serial and TLVs.
#[inline(never)]
pub fn write_keymap(
    s: &mut StoragePort<'_>,
    layout: u8,
    table: Option<&[u8; KEYMAP_BYTES]>,
) -> Result<(), StorageError> {
    Page::with_page(s, true, |page, s, persisted| {
        let old_flags = page.flags();
        let flags = (old_flags & !KEYMAP_VALID) | if table.is_some() { KEYMAP_VALID } else { 0 };
        let same_table = match table {
            Some(table) => page.0[KEYMAP_OFFSET..KEYMAP_END] == table[..],
            None => page.0[KEYMAP_OFFSET..KEYMAP_END].iter().all(|&v| v == 0),
        };
        if persisted
            && flags == old_flags
            && same_table
            && page.0[KEYMAP_HEADER_OFFSET..KEYMAP_HEADER_END] == keymap_header(layout)
        {
            return Ok(());
        }
        page.0[KEYMAP_HEADER_OFFSET..KEYMAP_HEADER_END].copy_from_slice(&keymap_header(layout));
        if let Some(table) = table {
            page.0[KEYMAP_OFFSET..KEYMAP_END].copy_from_slice(table);
        } else {
            page.0[KEYMAP_OFFSET..KEYMAP_END].fill(0);
        }
        page.0[FLAGS_OFFSET..SERIAL_OFFSET].copy_from_slice(&flags.to_ne_bytes());
        page.commit(s)
    })
}
#[inline(never)]
pub fn read_keymap(
    s: &mut StoragePort<'_>,
    table: &mut [u8; KEYMAP_BYTES],
) -> Result<u8, StorageError> {
    Page::with_page(s, false, |page, _, _| {
        if !page.has_keymap() {
            return Err(StorageError::Missing);
        }
        table.copy_from_slice(&page.0[KEYMAP_OFFSET..KEYMAP_END]);
        Ok(page.0[KEYMAP_HEADER_OFFSET])
    })
}
/// A stored zero usage suppresses the character; it never falls back to US.
#[inline(never)]
pub fn keyboard_usage(s: &mut StoragePort<'_>, ch: u8) -> Option<(u8, u8)> {
    if usize::from(ch) < KEYMAP_ENTRY_COUNT {
        let stored = Page::with_page(s, false, |page, _, _| {
            if !page.has_keymap() {
                return Err(StorageError::Missing);
            }
            let offset = KEYMAP_OFFSET + usize::from(ch) * KEYMAP_ENTRY_BYTES;
            Ok((page.0[offset + 1] != 0).then_some((page.0[offset], page.0[offset + 1])))
        });
        if let Ok(usage) = stored {
            return usage;
        }
    }
    super::keyboard::ascii(ch)
}

/// Recovery deliberately operates on raw pages, including corrupt metadata.
/// P2=0 preserves every non-loader byte; P2=1 erases metadata as on legacy CIU.
#[inline(never)]
pub fn recovery(s: &mut StoragePort<'_>, word: u32, erase: bool) -> Result<(), StorageError> {
    let mut page = Page([0xff; PAGE_BYTES]);
    if !erase {
        s.config_read(0, &mut page.0)?;
    }
    page.0[..MAGIC_OFFSET].copy_from_slice(&word.to_ne_bytes());
    s.config_write(&page.0)
}
