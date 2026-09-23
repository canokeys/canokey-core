// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
/// IDs belong exclusively to the new /rust namespace, never legacy C files.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Record {
    Pass = 0,
    AdminPin = 1,
    OathMetadata = 2,
    OathRecords = 3,
    PgpState = 4,
    PgpPw1 = 5,
    PgpPw3 = 6,
    PgpRc = 7,
    PgpSig = 8,
    PgpDec = 9,
    PgpAut = 10,
    PgpCertSig = 11,
    PgpCertDec = 12,
    PgpCertAut = 13,
    PivState = 14,
    PivDiscovery = 15,
}
#[derive(Clone, Copy, Debug)]
pub enum StorageError {
    Missing,
    Unavailable,
    Uncertain,
}
pub trait Storage {
    /// A single session-scoped staged object, separate from record replacements.
    /// Publication is atomic; abort/disconnect must discard unpublished bytes.
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "openpgp")]
    fn stage_append(&mut self, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "openpgp")]
    fn stage_commit(&mut self, _record: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(feature = "openpgp")]
    fn stage_abort(&mut self) {}
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
    fn replace_at(
        &mut self,
        _record: Record,
        _offset: u32,
        _input: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn has_space(&mut self, _bytes: u32, _reserve: u32) -> Result<bool, StorageError> {
        Err(StorageError::Unavailable)
    }
    fn load(&mut self, record: Record, output: &mut [u8]) -> Result<usize, StorageError>;
    /// Atomic replacement. Any failed mutation invalidates cached state.
    fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError>;
}
