// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
use crate::canokey::Record;

/// Staged-record operation codes, also projected into native_platform.h.
pub mod stage_operation {
    pub const BEGIN: u8 = 0x00;
    pub const APPEND: u8 = 0x01;
    pub const PUBLISH: u8 = 0x02;
    pub const ABORT: u8 = 0x03;
    pub const REMOVE: u8 = 0x04;
    pub const RENAME: u8 = 0x05;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    Missing,
    Unavailable,
    Uncertain,
}
/// `Storage::record_sizes` marker for an absent record. LittleFS files are
/// bounded by `0x7fffffff` bytes, so no record has this size.
pub const RECORD_ABSENT: u32 = u32::MAX;
/// CanoKey record service. Path-based engines and other products need not use
/// this record namespace or its resident-credential capacity.
pub trait Storage {
    /// Replace the unpublished staged object with borrowed pieces in one call.
    /// No handle or borrow survives the call; publication still needs commit.
    #[cfg(any(feature = "openpgp", feature = "piv", feature = "ctap"))]
    fn stage_parts(&mut self, parts: &[&[u8]]) -> Result<(), StorageError> {
        let result = (|| {
            self.stage_begin()?;
            for part in parts {
                self.stage_append(part)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.stage_abort();
        }
        result
    }
    /// Allocated filesystem bytes and total capacity, including metadata.
    fn usage(&mut self) -> Result<(u32, u32), StorageError> {
        Err(StorageError::Unavailable)
    }

    /// Raw platform configuration page. Missing means an unprovisioned/test
    /// backend; other read failures must not enable restricted interfaces.
    fn config_read(&mut self, _offset: usize, _bytes: &mut [u8]) -> Result<(), StorageError> {
        Err(StorageError::Missing)
    }
    /// Replace the entire aligned 512-byte page. A failure has uncertain outcome.
    fn config_write(&mut self, _bytes: &[u8; 512]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    /// A single session-scoped staged object, separate from record replacements.
    /// Publication is atomic; abort/disconnect must discard unpublished bytes.
    /// Appends need not be durable before publication. A backend may lease its
    /// shared file cache until commit/abort or another storage operation needs it.
    #[cfg(feature = "storage-staging")]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "storage-staging")]
    fn stage_append(&mut self, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "storage-staging")]
    fn stage_commit(&mut self, _record: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "storage-staging")]
    fn stage_abort(&mut self) {}
    /// Delete the record, treating an absent record as success. Empty data is
    /// not equivalent to absence for applets that validate persistent records.
    #[cfg(any(feature = "piv", feature = "ctap"))]
    fn remove(&mut self, _id: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "piv")]
    fn move_record(&mut self, _from: Record, _to: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn size(&mut self, _record: Record) -> Result<u32, StorageError> {
        Err(StorageError::Unavailable)
    }
    /// Fill `sizes[i]` with the logical size of record `first + i`, or
    /// [`RECORD_ABSENT`] when it does not exist; IDs past the namespace end are absent.
    /// An error reading any requested record fails the call. Backends with a
    /// directory listing can also report malformed entries in the same scan.
    fn record_sizes(&mut self, first: u8, sizes: &mut [u32]) -> Result<(), StorageError> {
        sizes.fill(RECORD_ABSENT);
        for (id, slot) in (first..Record::COUNT as u8).zip(sizes.iter_mut()) {
            *slot = match self.size(Record::from_id(id).unwrap()) {
                Ok(size) => size,
                Err(StorageError::Missing) => RECORD_ABSENT,
                Err(error) => return Err(error),
            };
        }
        Ok(())
    }
    fn read_at(
        &mut self,
        _record: Record,
        _offset: u32,
        _output: &mut [u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    /// Read a prefix of the requested window. Only the returned byte count is
    /// initialized; it must not exceed output.len(). Zero means no progress.
    /// Exact-only backends keep their existing failure semantics by default.
    #[cfg(feature = "ctap")]
    fn read_some_at(
        &mut self,
        record: Record,
        offset: u32,
        output: &mut [u8],
    ) -> Result<usize, StorageError> {
        self.read_at(record, offset, output)?;
        Ok(output.len())
    }
    /// Atomically patch one existing record, optionally extending it from an
    /// offset at or before EOF. A failed mutation has uncertain outcome and
    /// requires cache invalidation. The backend may use its filesystem's own
    /// transaction; an additional whole-file staging copy is not required.
    fn replace_at(
        &mut self,
        _record: Record,
        _offset: u32,
        _input: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "ndef")]
    fn resize(&mut self, _record: Record, _length: u32) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn has_space(&mut self, _bytes: u32, _reserve: u32) -> Result<bool, StorageError> {
        Err(StorageError::Unavailable)
    }
    fn load(&mut self, record: Record, output: &mut [u8]) -> Result<usize, StorageError>;
    /// Atomic replacement. Any failed mutation invalidates cached state.
    fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records `0x00`, `0x50` and the last ID exist; `0x51` fails to read.
    struct Lookups {
        fail: bool,
    }
    impl Storage for Lookups {
        fn size(&mut self, record: Record) -> Result<u32, StorageError> {
            match record.id() {
                0x00 => Ok(1),
                0x50 => Ok(2),
                0x51 if self.fail => Err(StorageError::Unavailable),
                id if usize::from(id) == Record::COUNT - 1 => Ok(3),
                _ => Err(StorageError::Missing),
            }
        }
        fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
            unreachable!()
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            unreachable!()
        }
    }

    #[test]
    fn default_record_sizes_bounds_ids_to_the_namespace() {
        let mut storage = Lookups { fail: false };
        let last = (Record::COUNT - 1) as u8;
        // A window past the namespace end, up to the u8 limit, is absent.
        let mut sizes = [0; 256];
        let window = 256 - usize::from(last);
        assert_eq!(storage.record_sizes(last, &mut sizes[..window]), Ok(()));
        assert_eq!(sizes[0], 3);
        assert!(sizes[1..window].iter().all(|&size| size == RECORD_ABSENT));
        // Every start at or beyond the end, including 0xFF, yields only absences.
        for first in [Record::COUNT as u8, u8::MAX] {
            sizes.fill(0);
            assert_eq!(storage.record_sizes(first, &mut sizes), Ok(()));
            assert!(sizes.iter().all(|&size| size == RECORD_ABSENT));
        }
        // Slots map to first + index; missing records are absent.
        let mut window = [0; 3];
        assert_eq!(storage.record_sizes(0x4f, &mut window), Ok(()));
        assert_eq!(window, [RECORD_ABSENT, 2, RECORD_ABSENT]);
        assert_eq!(storage.record_sizes(0, &mut []), Ok(()));
        // A read error other than Missing fails the whole call.
        storage.fail = true;
        assert_eq!(
            storage.record_sizes(0x50, &mut window),
            Err(StorageError::Unavailable)
        );
    }
}
