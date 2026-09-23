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
    PivManagement = 16,
    PivConfig = 17,
    PivKey0 = 18,
    PivKey1 = 19,
    PivKey2 = 20,
    PivKey3 = 21,
    PivKey4 = 22,
    PivKey5 = 23,
    PivKey6 = 24,
    PivKey7 = 25,
    PivKey8 = 26,
    PivKey9 = 27,
    PivKey10 = 28,
    PivKey11 = 29,
    PivKey12 = 30,
    PivKey13 = 31,
    PivKey14 = 32,
    PivKey15 = 33,
    PivKey16 = 34,
    PivKey17 = 35,
    PivKey18 = 36,
    PivKey19 = 37,
    PivKey20 = 38,
    PivKey21 = 39,
    PivKey22 = 40,
    PivKey23 = 41,
    PivKey24 = 42,
    PivObject0 = 43,
    PivObject1 = 44,
    PivObject2 = 45,
    PivObject3 = 46,
    PivObject4 = 47,
    PivObject5 = 48,
    PivObject6 = 49,
    PivObject7 = 50,
    PivObject8 = 51,
    PivObject9 = 52,
    PivObject10 = 53,
    PivObject11 = 54,
    PivObject12 = 55,
    PivObject13 = 56,
    PivObject14 = 57,
    PivObject15 = 58,
    PivObject16 = 59,
    PivObject17 = 60,
    PivObject18 = 61,
    PivObject19 = 62,
    PivObject20 = 63,
    PivObject21 = 64,
    PivObject22 = 65,
    PivObject23 = 66,
    PivObject24 = 67,
    PivObject25 = 68,
    PivObject26 = 69,
    PivObject27 = 70,
    PivObject28 = 71,
    PivObject29 = 72,
    PivObject30 = 73,
    PivObject31 = 74,
    PivObject32 = 75,
    PivObject33 = 76,
    PivProvision = 77,
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
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_append(&mut self, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_commit(&mut self, _record: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_abort(&mut self) {}
    #[cfg(feature = "piv")]
    fn remove(&mut self, id: Record) -> Result<(), StorageError> {
        self.replace(id, &[])
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
