// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
/// Record IDs map directly to two hexadecimal filename characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Record(u8);
#[allow(non_upper_case_globals)]
impl Record {
    pub const Pass: Self = Self(0);
    pub const AdminPin: Self = Self(1);
    pub const OathMetadata: Self = Self(2);
    pub const OathRecords: Self = Self(3);
    pub const PgpState: Self = Self(4);
    pub const PgpPw1: Self = Self(5);
    pub const PgpPw3: Self = Self(6);
    pub const PgpRc: Self = Self(7);
    pub const PgpSig: Self = Self(8);
    pub const PgpDec: Self = Self(9);
    pub const PgpAut: Self = Self(10);
    pub const PgpCertSig: Self = Self(11);
    pub const PgpCertDec: Self = Self(12);
    pub const PgpCertAut: Self = Self(13);
    pub const PivState: Self = Self(14);
    pub const PivManagement: Self = Self(15);
    pub const PivConfig: Self = Self(16);
    pub const PivKey0: Self = Self(17);
    pub const PivKey1: Self = Self(18);
    pub const PivKey2: Self = Self(19);
    pub const PivKey3: Self = Self(20);
    pub const PivKey4: Self = Self(21);
    pub const PivKey5: Self = Self(22);
    pub const PivKey6: Self = Self(23);
    pub const PivKey7: Self = Self(24);
    pub const PivKey8: Self = Self(25);
    pub const PivKey9: Self = Self(26);
    pub const PivKey10: Self = Self(27);
    pub const PivKey11: Self = Self(28);
    pub const PivKey12: Self = Self(29);
    pub const PivKey13: Self = Self(30);
    pub const PivKey14: Self = Self(31);
    pub const PivKey15: Self = Self(32);
    pub const PivKey16: Self = Self(33);
    pub const PivKey17: Self = Self(34);
    pub const PivKey18: Self = Self(35);
    pub const PivKey19: Self = Self(36);
    pub const PivKey20: Self = Self(37);
    pub const PivKey21: Self = Self(38);
    pub const PivKey22: Self = Self(39);
    pub const PivKey23: Self = Self(40);
    pub const PivKey24: Self = Self(41);
    pub const PivObject0: Self = Self(42);
    pub const PivObject1: Self = Self(43);
    pub const PivObject2: Self = Self(44);
    pub const PivObject3: Self = Self(45);
    pub const PivObject4: Self = Self(46);
    pub const PivObject5: Self = Self(47);
    pub const PivObject6: Self = Self(48);
    pub const PivObject7: Self = Self(49);
    pub const PivObject8: Self = Self(50);
    pub const PivObject9: Self = Self(51);
    pub const PivObject10: Self = Self(52);
    pub const PivObject11: Self = Self(53);
    pub const PivObject12: Self = Self(54);
    pub const PivObject13: Self = Self(55);
    pub const PivObject14: Self = Self(56);
    pub const PivObject15: Self = Self(57);
    pub const PivObject16: Self = Self(58);
    pub const PivObject17: Self = Self(59);
    pub const PivObject18: Self = Self(60);
    pub const PivObject19: Self = Self(61);
    pub const PivObject20: Self = Self(62);
    pub const PivObject21: Self = Self(63);
    pub const PivObject22: Self = Self(64);
    pub const PivObject23: Self = Self(65);
    pub const PivObject24: Self = Self(66);
    pub const PivObject25: Self = Self(67);
    pub const PivObject26: Self = Self(68);
    pub const PivObject27: Self = Self(69);
    pub const PivObject28: Self = Self(70);
    pub const PivObject29: Self = Self(71);
    pub const PivObject30: Self = Self(72);
    pub const PivObject31: Self = Self(73);
    pub const PivObject32: Self = Self(74);
    pub const PivObject33: Self = Self(75);
    pub const PivProvision: Self = Self(76);
    pub const CtapPin: Self = Self(77);
    pub const CtapMaster: Self = Self(78);
    pub const CtapCounter: Self = Self(79);
    pub const CtapLargeBlob: Self = Self(180);
    pub const CtapSm2: Self = Self(181);
    pub const CtapAttestationKey: Self = Self(182);
    pub const CtapCertificate: Self = Self(183);
    pub const fn id(self) -> u8 {
        self.0
    }
    pub const CTAP_CREDENTIALS: u8 = 100;
    const CTAP_CREDENTIAL_BASE: u8 = 0x50;
    pub const fn ctap_credential(index: u8) -> Option<Self> {
        if index < Self::CTAP_CREDENTIALS {
            // CTAP resident credentials occupy the contiguous 0x50..0xb3
            // range; 0xb4..0xb7 remain reserved for future records.
            Some(Self(Self::CTAP_CREDENTIAL_BASE + index))
        } else {
            None
        }
    }
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
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    fn stage_append(&mut self, _bytes: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    fn stage_commit(&mut self, _record: Record) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
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
pub fn copy_to_stage(
    storage: &mut crate::StoragePort<'_>,
    memory: &crate::MemoryPort<'_>,
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
