// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
/// Record IDs map directly to two hexadecimal filename characters.
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
    PivManagement = 15,
    PivConfig = 16,
    PivKey0 = 17,
    PivKey1 = 18,
    PivKey2 = 19,
    PivKey3 = 20,
    PivKey4 = 21,
    PivKey5 = 22,
    PivKey6 = 23,
    PivKey7 = 24,
    PivKey8 = 25,
    PivKey9 = 26,
    PivKey10 = 27,
    PivKey11 = 28,
    PivKey12 = 29,
    PivKey13 = 30,
    PivKey14 = 31,
    PivKey15 = 32,
    PivKey16 = 33,
    PivKey17 = 34,
    PivKey18 = 35,
    PivKey19 = 36,
    PivKey20 = 37,
    PivKey21 = 38,
    PivKey22 = 39,
    PivKey23 = 40,
    PivKey24 = 41,
    PivObject0 = 42,
    PivObject1 = 43,
    PivObject2 = 44,
    PivObject3 = 45,
    PivObject4 = 46,
    PivObject5 = 47,
    PivObject6 = 48,
    PivObject7 = 49,
    PivObject8 = 50,
    PivObject9 = 51,
    PivObject10 = 52,
    PivObject11 = 53,
    PivObject12 = 54,
    PivObject13 = 55,
    PivObject14 = 56,
    PivObject15 = 57,
    PivObject16 = 58,
    PivObject17 = 59,
    PivObject18 = 60,
    PivObject19 = 61,
    PivObject20 = 62,
    PivObject21 = 63,
    PivObject22 = 64,
    PivObject23 = 65,
    PivObject24 = 66,
    PivObject25 = 67,
    PivObject26 = 68,
    PivObject27 = 69,
    PivObject28 = 70,
    PivObject29 = 71,
    PivObject30 = 72,
    PivObject31 = 73,
    PivObject32 = 74,
    PivObject33 = 75,
    PivProvision = 76,
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
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn stage_append(&mut self, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn stage_commit(&mut self, _record: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
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

/// Copy a bounded window into an active staging transaction, wiping temporary data.
#[cfg(any(feature = "oath", feature = "piv"))]
pub(crate) fn copy_to_stage(
    storage: &mut dyn Storage,
    memory: &dyn super::Memory,
    record: Record,
    mut offset: u32,
    mut length: u32,
) -> Result<(), StorageError> {
    let mut buffer = [0; 128];
    let result = (|| {
        while length != 0 {
            let n = length.min(buffer.len() as u32) as usize;
            storage.read_at(record, offset, &mut buffer[..n])?;
            storage.stage_append(&buffer[..n])?;
            offset += n as u32;
            length -= n as u32;
        }
        Ok(())
    })();
    memory.wipe(&mut buffer);
    result
}
