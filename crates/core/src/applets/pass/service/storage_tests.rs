// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::ports::{Memory, Storage};

struct Disk {
    bytes: [u8; FILE_SIZE],
    length: Option<usize>,
    fail: bool,
    applied: bool,
    patches: usize,
    last: (u32, usize),
}
impl Disk {
    fn new() -> Self {
        Self {
            bytes: [0; FILE_SIZE],
            length: None,
            fail: false,
            applied: false,
            patches: 0,
            last: (0, 0),
        }
    }
}
impl Storage for Disk {
    fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        assert_eq!(id, Record::Pass);
        let n = self.length.ok_or(StorageError::Missing)?;
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
    fn replace(&mut self, _: Record, input: &[u8]) -> Result<(), StorageError> {
        assert!(
            self.length.is_none(),
            "only initialization replaces the file"
        );
        self.bytes.copy_from_slice(input);
        self.length = Some(input.len());
        Ok(())
    }
    fn replace_at(&mut self, _: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        assert_eq!(self.length, Some(FILE_SIZE));
        self.patches += 1;
        self.last = (offset, input.len());
        if !self.fail || self.applied {
            self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        }
        if self.fail {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

#[test]
fn fixed_slot_patches_preserve_other_slot_and_reject_old_layouts() {
    let mut disk = Disk::new();
    let mut pass = Pass::new();
    pass.install(&mut disk, &Wipe).unwrap();
    pass.configure(
        SlotIndex::new(1).unwrap(),
        Slot::Hmac(&[7; 20]),
        &mut disk,
        &Wipe,
    )
    .unwrap();
    let other: [u8; 72] = disk.bytes[72..].try_into().unwrap();
    pass.configure(
        SlotIndex::new(0).unwrap(),
        Slot::Static {
            password: b"one",
            enter: 1,
        },
        &mut disk,
        &Wipe,
    )
    .unwrap();
    assert_eq!(disk.last, (0, 72));
    assert_eq!(disk.bytes[72..], other);
    pass.install(&mut disk, &Wipe).unwrap();
    assert!(matches!(
        pass.slot(0),
        Ok(Slot::Static {
            password: b"one",
            enter: 1
        })
    ));
    assert!(matches!(pass.slot(1), Ok(Slot::Hmac(key)) if key == &[7; 20]));
    disk.bytes[0] = 2;
    assert_eq!(pass.install(&mut disk, &Wipe), Err(Error::Persistence));
    assert!(pass.records().is_err());
    disk.bytes[0] = 3;
    disk.length = Some(8);
    assert_eq!(pass.install(&mut disk, &Wipe), Err(Error::Persistence));
}

#[test]
fn uncertain_slot_patch_wipes_cache_and_requires_reload() {
    for applied in [false, true] {
        let mut disk = Disk::new();
        let mut pass = Pass::new();
        pass.install(&mut disk, &Wipe).unwrap();
        disk.fail = true;
        disk.applied = applied;
        assert_eq!(
            pass.configure(
                SlotIndex::new(0).unwrap(),
                Slot::Hmac(&[9; 20]),
                &mut disk,
                &Wipe
            ),
            Err(Error::Persistence)
        );
        assert!(pass.records().is_err());
        assert!(pass.slots.iter().all(|&v| v == 0));
        disk.fail = false;
        pass.install(&mut disk, &Wipe).unwrap();
        assert_eq!(matches!(pass.slot(0), Ok(Slot::Hmac(_))), applied);
    }
}

#[test]
fn clear_publishes_both_slots_once() {
    let mut disk = Disk::new();
    let mut pass = Pass::new();
    pass.install(&mut disk, &Wipe).unwrap();
    for index in 0..2 {
        pass.configure(
            SlotIndex::new(index).unwrap(),
            Slot::Hmac(&[9; 20]),
            &mut disk,
            &Wipe,
        )
        .unwrap();
    }
    let patches = disk.patches;
    pass.clear(&mut disk, &Wipe).unwrap();
    assert_eq!(disk.patches, patches + 1);
    assert_eq!(disk.last, (0, FILE_SIZE));
    pass.install(&mut disk, &Wipe).unwrap();
    assert!(matches!(pass.slot(0), Ok(Slot::Off)));
    assert!(matches!(pass.slot(1), Ok(Slot::Off)));
}
