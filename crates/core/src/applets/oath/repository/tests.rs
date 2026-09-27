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
    capacity: Cell<Option<u32>>,
    reserve: Cell<u32>,
    forbidden_read: Cell<Option<(usize, usize)>>,
    patches: Cell<usize>,
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
    fn replace_at(
        &mut self,
        record: Record,
        offset: u32,
        input: &[u8],
    ) -> Result<(), StorageError> {
        assert_eq!(record, Record::OathRecords);
        self.controls.patches.set(self.controls.patches.get() + 1);
        self.bytes
            .resize(self.bytes.len().max(offset as usize + input.len()), 0);
        self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
        if self.controls.uncertain_commit.replace(false) {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        assert_eq!(record, Record::OathRecords);
        Ok(self.bytes.len() as u32)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        assert_eq!(record, Record::OathRecords);
        if let Some((start, end)) = self.controls.forbidden_read.get()
            && (offset as usize) < end
            && offset as usize + out.len() > start
        {
            return Err(StorageError::Unavailable);
        }
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
    fn has_space(&mut self, needed: u32, reserve: u32) -> Result<bool, StorageError> {
        self.controls.reserve.set(reserve);
        Ok(self.controls.capacity.get().is_none_or(|capacity| {
            (self.bytes.len() as u32)
                .checked_add(needed)
                .and_then(|used| used.checked_add(reserve))
                .is_some_and(|used| used <= capacity)
        }))
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.stage.clear();
        Ok(())
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        if self.controls.capacity.get().is_some_and(|capacity| {
            self.bytes.len() + self.stage.len() + bytes.len() > capacity as usize
        }) {
            return Err(StorageError::Unavailable);
        }
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

struct NoCrypto;
impl Crypto for NoCrypto {
    fn hmac(&mut self, _: Algorithm, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), Error> {
        panic!("metadata must not use crypto")
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), Error> {
        panic!("metadata must not use crypto")
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
#[test]
fn metadata_search_never_reads_secret_and_counter_patch_preserves_record() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let id = {
        let mut store = Store::new(&mut files, &Wipe);
        store.initialize().unwrap();
        store.insert(&credential(b"first")).unwrap()
    };
    let original = files.bytes.clone();
    controls.patches.set(0);
    let key_start = FILE_HEADER_BYTES as usize + ID_BYTES + codec::KEY_OFFSET;
    controls
        .forbidden_read
        .set(Some((key_start, key_start + 20)));
    {
        let mut store = Store::new(&mut files, &Wipe);
        assert!(store.matches_name(id, b"first", &mut NoCrypto).unwrap());
        assert!(!store.matches_name(id, b"other", &mut NoCrypto).unwrap());
        assert!(matches!(store.metadata(id).unwrap().kind, Kind::Totp));
        assert!(matches!(store.load(id), Err(Error::Storage)));
        store.update_counter(id, &123u64.to_be_bytes()).unwrap();
        assert_eq!(controls.patches.get(), 1);
        controls.uncertain_commit.set(true);
        assert_eq!(
            store.update_counter(id, &124u64.to_be_bytes()),
            Err(Error::Storage)
        );
        let reads = controls.header_reads.get();
        store.metadata(id).unwrap();
        assert_eq!(controls.header_reads.get(), reads + 1);
    }
    let end = original.len() - 8;
    assert_eq!(&files.bytes[..end], &original[..end]);
    assert_eq!(&files.bytes[end..], &124u64.to_be_bytes());
    assert!(files.stage.is_empty());
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
#[test]
fn successful_load_erases_its_read_buffer_before_returning_the_owned_record() {
    struct Observe(Cell<usize>);
    impl Memory for Observe {
        fn wipe(&self, bytes: &mut [u8]) {
            if bytes.len() == codec::LENGTH
                && bytes.windows(20).any(|v| v == b"12345678901234567890")
            {
                self.0.set(self.0.get() + 1);
            }
            bytes.fill(0);
        }
    }
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let id = {
        let mut store = Store::new(&mut files, &Wipe);
        store.initialize().unwrap();
        store.insert(&credential(b"first")).unwrap()
    };
    let memory = Observe(Cell::new(0));
    let mut store = Store::new(&mut files, &memory);
    let mut loaded = store.load(id).unwrap();
    assert_eq!(memory.0.get(), 1);
    assert_eq!(loaded.key(), b"12345678901234567890");
    loaded.clear(&mut NoCrypto);
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
fn deletion_erases_slot_and_retains_id_across_empty_reload_and_reuse() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let id = {
        let mut store = Store::new(&mut files, &Wipe);
        store.initialize().unwrap();
        let id = store.insert(&credential(b"secret name")).unwrap();
        store.delete(id).unwrap();
        id
    };
    assert_eq!(&files.bytes[..4], b"OAT2");
    assert_eq!(files.bytes.len(), 150);
    assert_eq!(&files.bytes[4..8], &id.0.to_be_bytes());
    assert!(files.bytes[8..].iter().all(|b| *b == 0));
    // Even when no file growth is allowed, a deleted slot remains reusable.
    controls.capacity.set(Some(files.bytes.len() as u32));
    let mut store = Store::new(&mut files, &Wipe);
    store.install().unwrap();
    assert_eq!(store.first().unwrap(), None);
    let fresh = store.insert(&credential(b"new")).unwrap();
    assert!(fresh.0 > id.0);
    assert!(matches!(store.load(id), Err(Error::Missing)));
    assert_eq!(store.load(fresh).unwrap().name(), b"new");
}

#[test]
fn rejects_previous_layout_and_id_exhaustion_without_writes() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: std::vec![0, 0, 0, 1],
        stage: Vec::new(),
        controls: &controls,
    };
    assert_eq!(Store::new(&mut files, &Wipe).install(), Err(Error::Storage));
    files.bytes = b"OAT2".to_vec();
    files.bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    files.bytes.extend_from_slice(&[0; 142]);
    let before = files.bytes.clone();
    let mut store = Store::new(&mut files, &Wipe);
    store.install().unwrap();
    assert_eq!(store.insert(&credential(b"no wrap")), Err(Error::NoSpace));
    assert_eq!(files.bytes, before);
    assert_eq!(controls.patches.get(), 0);
}

#[test]
fn enumeration_reuses_validated_header_and_recycles_slots_without_reusing_ids() {
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
    assert_eq!(store.first().unwrap(), Some(third));
    assert_eq!(store.next(third).unwrap(), Some(second));
    assert_eq!(store.next(second).unwrap(), None);
    assert_eq!(store.load(third).unwrap().name(), b"third");
}

#[test]
fn uncertain_replacement_and_reinitialization_discard_cached_boundaries() {
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

#[test]
fn capacity_exceeds_one_hundred_and_reserves_delete_and_reinsert_space() {
    let controls = Controls::default();
    // A finite device. Exhausting the growth reserve must still allow deletion
    // and reuse of an existing slot, without asking for another slot's space.
    controls.capacity.set(Some(96 * 1024));
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let mut ids = Vec::new();
    {
        let mut store = Store::new(&mut files, &Wipe);
        store.initialize().unwrap();
        for index in 0u32..2048 {
            match store.insert(&credential(&index.to_be_bytes())) {
                Ok(id) => ids.push(id),
                Err(Error::NoSpace) => break,
                other => panic!("unexpected insertion result: {other:?}"),
            }
        }
        assert!(ids.len() > 100 && ids.len() < 2048);
        assert_eq!(controls.reserve.get(), 64 * 1024);
    }
    let original = files.bytes.clone();
    {
        let mut store = Store::new(&mut files, &Wipe);
        assert_eq!(store.insert(&credential(b"next")), Err(Error::NoSpace));
    }
    assert_eq!(files.bytes, original);
    assert!(files.stage.is_empty());
    {
        let mut store = Store::new(&mut files, &Wipe);
        store.delete(ids[0]).unwrap();
        let replacement = store.insert(&credential(&0u32.to_be_bytes())).unwrap();
        assert!(replacement.0 > ids.last().unwrap().0);
        assert!(matches!(store.load(ids[0]), Err(Error::Missing)));
        assert_eq!(store.load(replacement).unwrap().name(), &0u32.to_be_bytes());
        for (index, id) in ids.iter().enumerate().skip(1) {
            assert_eq!(
                store.load(*id).unwrap().name(),
                &(index as u32).to_be_bytes()
            );
        }
    }
    assert_eq!(files.bytes.len(), original.len());
}
