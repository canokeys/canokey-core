// SPDX-License-Identifier: Apache-2.0
extern crate std;

use super::*;
use crate::applets::oath::credential::{Kind, Properties};
use crate::ports::{Memory, Storage};
use core::cell::Cell;
use std::vec::Vec;

#[derive(Default)]
struct Controls {
    header_reads: Cell<usize>,
    uncertain_commit: Cell<bool>,
}
struct Files<'a> {
    bytes: Vec<u8>,
    stage: Vec<u8>,
    controls: &'a Controls,
}
impl Storage for Files<'_> {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        panic!("record traversal must use bounded reads")
    }
    fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError> {
        assert_eq!(record, Record::OathRecords);
        self.bytes = input.to_vec();
        Ok(())
    }
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        assert_eq!(record, Record::OathRecords);
        Ok(self.bytes.len() as u32)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        assert_eq!(record, Record::OathRecords);
        if out.len() == ENTRY_HEADER_BYTES {
            self.controls
                .header_reads
                .set(self.controls.header_reads.get() + 1);
        }
        let source = self
            .bytes
            .get(offset as usize..offset as usize + out.len())
            .ok_or(StorageError::Unavailable)?;
        out.copy_from_slice(source);
        Ok(())
    }
    fn has_space(&mut self, _: u32, _: u32) -> Result<bool, StorageError> {
        Ok(true)
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.stage.clear();
        Ok(())
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.stage.extend_from_slice(bytes);
        Ok(())
    }
    fn stage_commit(&mut self, record: Record) -> Result<(), StorageError> {
        assert_eq!(record, Record::OathRecords);
        self.bytes = core::mem::take(&mut self.stage);
        if self.controls.uncertain_commit.replace(false) {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
    fn stage_abort(&mut self) {
        self.stage.clear();
    }
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
fn credential(name: &[u8]) -> Credential {
    Credential::new(
        name,
        b"12345678901234567890",
        Kind::Totp,
        Algorithm::Sha1,
        6,
        Properties::new(0).unwrap(),
        [0; 8],
    )
    .unwrap()
}

#[test]
fn enumeration_reuses_validated_header_and_tracks_resized_records() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let mut store = Store::new(&mut files, &Wipe);
    store.initialize().unwrap();
    let first = store.insert(&credential(b"first")).unwrap();
    let second = store.insert(&credential(b"second")).unwrap();
    controls.header_reads.set(0);
    assert_eq!(store.first().unwrap(), Some(first));
    assert_eq!(store.load(first).unwrap().name(), b"first");
    assert_eq!(store.next(first).unwrap(), Some(second));
    assert_eq!(store.load(second).unwrap().name(), b"second");
    assert_eq!(store.next(second).unwrap(), None);
    assert_eq!(controls.header_reads.get(), 2);

    store
        .replace(first, &credential(b"a much longer first name"))
        .unwrap();
    assert_eq!(
        store.load(first).unwrap().name(),
        b"a much longer first name"
    );
    assert_eq!(store.next(first).unwrap(), Some(second));
    assert_eq!(store.load(second).unwrap().name(), b"second");
    store.delete(first).unwrap();
    assert_eq!(store.first().unwrap(), Some(second));
    assert!(matches!(store.load(first), Err(Error::Missing)));
    let third = store.insert(&credential(b"third")).unwrap();
    assert!(third.0 > second.0);
    assert_eq!(store.next(second).unwrap(), Some(third));
    assert_eq!(store.load(third).unwrap().name(), b"third");
}

#[test]
fn uncertain_resize_and_reinitialization_discard_cached_boundaries() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let mut store = Store::new(&mut files, &Wipe);
    store.initialize().unwrap();
    let id = store.insert(&credential(b"short")).unwrap();
    assert_eq!(store.load(id).unwrap().name(), b"short");
    controls.uncertain_commit.set(true);
    assert_eq!(
        store.replace(id, &credential(b"longer after uncertain commit")),
        Err(Error::Storage)
    );
    store.install().unwrap();
    assert_eq!(
        store.load(id).unwrap().name(),
        b"longer after uncertain commit"
    );
    store.initialize().unwrap();
    assert!(matches!(store.load(id), Err(Error::Missing)));
    assert_eq!(store.first().unwrap(), None);
}

#[test]
fn truncated_or_invalid_entry_headers_fail_closed() {
    for bytes in [
        std::vec![0, 0, 0, 2, 0, 0, 0, 1],
        // Valid version/lengths but no payload.
        std::vec![0, 0, 0, 2, 0, 0, 0, 1, 1, 5, 20, 0x21, 6, 0],
        // A zero stable ID is never a live entry.
        std::vec![0, 0, 0, 2, 0, 0, 0, 0, 1, 1, 1, 0x21, 6, 0],
    ] {
        let controls = Controls::default();
        let mut files = Files {
            bytes,
            stage: Vec::new(),
            controls: &controls,
        };
        let mut store = Store::new(&mut files, &Wipe);
        assert_eq!(store.first(), Err(Error::Storage));
    }
}
