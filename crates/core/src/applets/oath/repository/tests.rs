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
    let key_start = FILE_HEADER_BYTES as usize + ENTRY_HEADER_BYTES + b"first".len();
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
fn load_reads_in_place_and_erases_the_destination_on_failure() {
    // Counts erasures of any record-sized buffer that still holds the key.
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
    let mut loaded = Credential::empty();
    store.load_into(id, &mut loaded).unwrap();
    // The key is read directly into the caller's record: no intermediate
    // key-bearing buffer exists, so nothing else needs erasing.
    assert_eq!(memory.0.get(), 0);
    assert_eq!(loaded.key(), b"12345678901234567890");
    loaded.clear(&mut NoCrypto);
    drop(store);
    // A failed read must not leave partial or stale key bytes in `out`.
    let key_start = FILE_HEADER_BYTES as usize + ENTRY_HEADER_BYTES + b"first".len();
    controls
        .forbidden_read
        .set(Some((key_start, key_start + 20)));
    let mut store = Store::new(&mut files, &Wipe);
    let mut failed = Credential::empty();
    failed.bytes.fill(0xa5);
    assert!(matches!(
        store.load_into(id, &mut failed),
        Err(Error::Storage)
    ));
    assert!(failed.bytes.iter().all(|&byte| byte == 0));
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
fn deletion_removes_the_entry_and_never_reuses_its_id() {
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
        // ID, header, name, 20-byte key and counter are packed without padding.
        assert_eq!(store.size().unwrap(), 8 + 4 + 6 + 11 + 20 + 8);
        store.delete(id).unwrap();
        id
    };
    // The deleted bytes are gone; the header keeps a bound above the old ID.
    assert_eq!(&files.bytes[..4], b"OAT3");
    assert_eq!(files.bytes.len(), 8);
    assert_eq!(&files.bytes[4..8], &(id.0 + 1).to_be_bytes());
    let mut store = Store::new(&mut files, &Wipe);
    store.install().unwrap();
    assert_eq!(store.first().unwrap(), None);
    let fresh = store.insert(&credential(b"new")).unwrap();
    assert!(fresh.0 > id.0);
    assert!(matches!(store.load(id), Err(Error::Missing)));
    assert_eq!(store.load(fresh).unwrap().name(), b"new");
}
#[test]
fn deletion_and_rename_leave_the_old_file_on_staging_failure() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: Vec::new(),
        stage: Vec::new(),
        controls: &controls,
    };
    let (first, second) = {
        let mut store = Store::new(&mut files, &Wipe);
        store.initialize().unwrap();
        (
            store.insert(&credential(b"first")).unwrap(),
            store.insert(&credential(b"second")).unwrap(),
        )
    };
    let original = files.bytes.clone();
    // No room for a staged copy: the published file must stay untouched.
    controls.capacity.set(Some(original.len() as u32 + 16));
    {
        let mut store = Store::new(&mut files, &Wipe);
        assert_eq!(store.delete(first), Err(Error::Storage));
        assert_eq!(
            store.replace(second, &credential(b"renamed")),
            Err(Error::Storage)
        );
    }
    assert_eq!(files.bytes, original);
    assert!(files.stage.is_empty());
}

#[test]
fn rejects_invalid_headers_and_id_exhaustion_without_writes() {
    let controls = Controls::default();
    let mut files = Files {
        bytes: std::vec![0, 0, 0, 1],
        stage: Vec::new(),
        controls: &controls,
    };
    assert_eq!(Store::new(&mut files, &Wipe).install(), Err(Error::Storage));
    // The fixed-slot OAT2 layout is not reinterpreted.
    files.bytes = b"OAT2".to_vec();
    files.bytes.extend_from_slice(&[0; 146]);
    assert_eq!(Store::new(&mut files, &Wipe).install(), Err(Error::Storage));
    files.bytes = b"OAT3\0\0\0\0".to_vec();
    let mut store = Store::new(&mut files, &Wipe);
    assert_eq!(store.install(), Err(Error::Storage));
    assert_eq!(
        store.insert(&credential(b"invalid ID")),
        Err(Error::Storage)
    );
    assert_eq!(files.bytes, b"OAT3\0\0\0\0");
    for next in [u32::MAX - 1, u32::MAX] {
        files.bytes = b"OAT3".to_vec();
        files.bytes.extend_from_slice(&next.to_be_bytes());
        let mut entry = [0; MAX_ENTRY_BYTES as usize];
        let n = encode(CredentialId(next), &credential(b"last"), &mut entry);
        files.bytes.extend_from_slice(&entry[..n]);
        let before = files.bytes.clone();
        let mut store = Store::new(&mut files, &Wipe);
        store.install().unwrap();
        assert_eq!(store.insert(&credential(b"no wrap")), Err(Error::NoSpace));
        assert_eq!(files.bytes, before);
        assert_eq!(controls.patches.get(), 0);
    }
}

#[test]
fn enumeration_reuses_validated_header_and_keeps_insertion_order_without_reusing_ids() {
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
    assert_eq!(store.first().unwrap(), Some(second));
    assert_eq!(store.next(second).unwrap(), Some(third));
    assert_eq!(store.next(third).unwrap(), None);
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
    const H: [u8; 8] = *b"OAT3\0\0\0\x01";
    let entry = |id: u8, version: u8| {
        let mut v = H.to_vec();
        v.extend_from_slice(&[0, 0, 0, id, version, 1, 1, 0x21, 6, 0, b'n', b'k']);
        v.extend_from_slice(&[0; 8]);
        v
    };
    let mut truncated = H.to_vec();
    truncated.extend_from_slice(&[0, 0, 0, 1]);
    // Valid version/lengths but no payload.
    let mut empty = H.to_vec();
    empty.extend_from_slice(&[0, 0, 0, 1, 2, 5, 20, 0x21, 6, 0]);
    // A zero stable ID and a fixed-slot version-zero tombstone are invalid.
    for bytes in [truncated, empty, entry(0, 2), entry(1, 0)] {
        let controls = Controls::default();
        let mut files = Files {
            bytes,
            stage: Vec::new(),
            controls: &controls,
        };
        let mut store = Store::new(&mut files, &Wipe);
        assert_eq!(store.first(), Err(Error::Storage));
    }
    // The same entry with a nonzero ID and version 2 is accepted.
    let controls = Controls::default();
    let mut files = Files {
        bytes: entry(1, 2),
        stage: Vec::new(),
        controls: &controls,
    };
    let mut store = Store::new(&mut files, &Wipe);
    assert_eq!(store.first(), Ok(Some(CredentialId(1))));
    assert_eq!(store.next(CredentialId(1)), Ok(None));
}

#[test]
fn capacity_exceeds_one_hundred_and_reserves_delete_and_reinsert_space() {
    let controls = Controls::default();
    // A finite device. Exhausting the growth reserve must still leave room to
    // stage the copy that deletion needs, then admit a replacement entry.
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
        let size = store.size().unwrap();
        assert_eq!(controls.reserve.get(), update_reserve(size));
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
