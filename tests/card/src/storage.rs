// SPDX-License-Identifier: Apache-2.0
use canokey_ports::{Record, Storage, StorageError};

// Match the historical in-memory fixture's record and unpublished-object limits.
const RECORD_BYTES: usize = 32768;
const STAGE_BYTES: usize = 8192;
const CAPACITY: u32 = 128 * 1024;
const METADATA_BYTES: u32 = 4096;
pub struct Records {
    files: [Option<Vec<u8>>; Record::COUNT],
    stage: Vec<u8>,
    config: [u8; 512],
    pub fail_read: Option<Record>,
    pub fail_write: Option<Record>,
}
impl Records {
    pub fn new() -> Self {
        Self {
            files: std::array::from_fn(|_| None),
            stage: Vec::with_capacity(STAGE_BYTES),
            config: [0xff; 512],
            fail_read: None,
            fail_write: None,
        }
    }
    fn bytes(&self, record: Record) -> Result<&[u8], StorageError> {
        self.files[record.id() as usize]
            .as_deref()
            .ok_or(StorageError::Missing)
    }
    fn write_fault(&mut self, record: Record) -> Result<(), StorageError> {
        if self.fail_write == Some(record) {
            self.fail_write = None;
            Err(StorageError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn read_fault(&mut self, record: Record) -> Result<(), StorageError> {
        if self.fail_read == Some(record) {
            self.fail_read = None;
            Err(StorageError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub fn corrupt(&mut self, record: Record, offset: usize, mask: u8) {
        self.files[record.id() as usize].as_mut().unwrap()[offset] ^= mask;
    }
    pub fn discard(&mut self, record: Record) {
        if let Some(mut bytes) = self.files[record.id() as usize].take() {
            bytes.fill(0);
        }
    }
}
impl Drop for Records {
    fn drop(&mut self) {
        self.stage.fill(0);
        for bytes in self.files.iter_mut().flatten() {
            bytes.fill(0);
        }
        self.config.fill(0);
    }
}
impl Storage for Records {
    fn usage(&mut self) -> Result<(u32, u32), StorageError> {
        let used = METADATA_BYTES
            + self
                .files
                .iter()
                .flatten()
                .map(|b| b.len() as u32)
                .sum::<u32>();
        if used > CAPACITY {
            Err(StorageError::Unavailable)
        } else {
            Ok((used, CAPACITY))
        }
    }
    fn config_read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), StorageError> {
        out.copy_from_slice(
            self.config
                .get(offset..offset + out.len())
                .ok_or(StorageError::Unavailable)?,
        );
        Ok(())
    }
    fn config_write(&mut self, bytes: &[u8; 512]) -> Result<(), StorageError> {
        self.config.copy_from_slice(bytes);
        Ok(())
    }
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        Ok(self.bytes(record)?.len() as u32)
    }
    fn load(&mut self, record: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        let bytes = self.bytes(record)?;
        let n = bytes.len();
        out.get_mut(..n)
            .ok_or(StorageError::Unavailable)?
            .copy_from_slice(bytes);
        // Supply private bytes before failure, as the original adversarial fixture did.
        self.read_fault(record)?;
        Ok(n)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        let start = offset as usize;
        out.copy_from_slice(
            self.bytes(record)?
                .get(start..start + out.len())
                .ok_or(StorageError::Unavailable)?,
        );
        self.read_fault(record)
    }
    fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError> {
        self.write_fault(record)?;
        assert!(input.len() <= RECORD_BYTES);
        self.discard(record);
        self.files[record.id() as usize] = Some(input.to_vec());
        Ok(())
    }
    fn replace_at(
        &mut self,
        record: Record,
        offset: u32,
        input: &[u8],
    ) -> Result<(), StorageError> {
        self.write_fault(record)?;
        let bytes = self.files[record.id() as usize]
            .as_mut()
            .ok_or(StorageError::Missing)?;
        let start = offset as usize;
        let end = start + input.len();
        if start > bytes.len() || end > RECORD_BYTES {
            return Err(StorageError::Unavailable);
        }
        bytes.resize(bytes.len().max(end), 0);
        bytes[start..end].copy_from_slice(input);
        Ok(())
    }
    fn has_space(&mut self, bytes: u32, _: u32) -> Result<bool, StorageError> {
        // OATH's reserve oracle historically considers only its own record.
        let used = self.files[Record::OathRecords.id() as usize]
            .as_ref()
            .map_or(0, Vec::len);
        Ok(bytes as usize + used <= RECORD_BYTES)
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.stage_abort();
        Ok(())
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        assert!(self.stage.len() + bytes.len() <= STAGE_BYTES);
        self.stage.extend_from_slice(bytes);
        Ok(())
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_commit(&mut self, record: Record) -> Result<(), StorageError> {
        let mut bytes = std::mem::take(&mut self.stage);
        let result = self.replace(record, &bytes);
        bytes.fill(0);
        result
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_abort(&mut self) {
        self.stage.fill(0);
        self.stage.clear();
    }
    #[cfg(any(feature = "piv", feature = "ctap"))]
    fn remove(&mut self, record: Record) -> Result<(), StorageError> {
        self.write_fault(record)?;
        self.discard(record);
        Ok(())
    }
    #[cfg(feature = "piv")]
    fn move_record(&mut self, from: Record, to: Record) -> Result<(), StorageError> {
        let bytes = self.bytes(from)?.to_vec();
        self.discard(to);
        self.files[to.id() as usize] = Some(bytes);
        self.discard(from);
        Ok(())
    }
    #[cfg(feature = "ndef")]
    fn resize(&mut self, record: Record, length: u32) -> Result<(), StorageError> {
        assert!(length as usize <= RECORD_BYTES);
        let bytes = self.files[record.id() as usize]
            .as_mut()
            .ok_or(StorageError::Missing)?;
        bytes.resize(length as usize, 0);
        Ok(())
    }
}
