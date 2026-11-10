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
