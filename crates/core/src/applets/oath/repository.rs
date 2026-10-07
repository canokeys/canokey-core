// SPDX-License-Identifier: Apache-2.0
//! Safe assembly adapters. Each backend borrow ends before the next service call.
#![forbid(unsafe_code)]
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth, codec,
    credential::Credential,
    service::{CredentialId, Repository},
};
use crate::ports::{CryptoPort, Record, StorageError};
pub struct Store<'a> {
    storage: &'a mut crate::ports::StoragePort<'a>,
    memory: &'a crate::ports::MemoryPort<'a>,
    located: Option<Entry>,
}
/// Validated record boundaries, local to this exclusive storage borrow.
/// Every record mutation invalidates them before attempting a write.
#[derive(Clone, Copy)]
struct Entry {
    id: CredentialId,
    offset: u32,
    end: u32,
    header: [u8; codec::HEADER_BYTES],
}
pub struct Mac<'a> {
    crypto: &'a mut CryptoPort<'a>,
    memory: &'a crate::ports::MemoryPort<'a>,
}
impl<'a> Store<'a> {
    pub fn new(
        storage: &'a mut crate::ports::StoragePort<'a>,
        memory: &'a crate::ports::MemoryPort<'a>,
    ) -> Self {
        Self {
            storage,
            memory,
            located: None,
        }
    }
}
impl<'a> Mac<'a> {
    pub fn new(crypto: &'a mut CryptoPort<'a>, memory: &'a crate::ports::MemoryPort<'a>) -> Self {
        Self { crypto, memory }
    }
}
const ID_BYTES: usize = 4;
const ENTRY_HEADER_BYTES: usize = ID_BYTES + codec::HEADER_BYTES;
const ENTRY_BYTES: u32 = (ID_BYTES + codec::LENGTH) as u32;
const STORAGE_PAGE_BYTES: u32 = 512;
// Measured 204-page CIU policy: metadata compaction margin above the projected
// OATH tail copy, with a 20 KiB floor for the primary mixed workload.
const METADATA_MARGIN_PAGES: u32 = 8;
const MIN_UPDATE_RESERVE_BYTES: u32 = 20 * 1024;
// Conservative durable growth for appending a fixed slot, including a CTZ page.
const PROJECTED_GROWTH_PAGES: u32 = 2;
// OATH-local admission margin, not a reservation enforced by other applets.
// A patch near the beginning can copy the entire surviving CTZ tail.
fn update_reserve(size: u32) -> u32 {
    let tail_pages = (size + ENTRY_BYTES).div_ceil(STORAGE_PAGE_BYTES);
    ((tail_pages + METADATA_MARGIN_PAGES) * STORAGE_PAGE_BYTES).max(MIN_UPDATE_RESERVE_BYTES)
}
// Distinguish fixed slots from every earlier encoding, including empty files.
const FILE_HEADER: &[u8; 4] = b"OAT2";
const FILE_HEADER_BYTES: u32 = FILE_HEADER.len() as u32;
fn io(_: StorageError) -> Error {
    Error::Storage
}
impl Crypto for Mac<'_> {
    fn hmac(
        &mut self,
        alg: Algorithm,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), Error> {
        self.crypto
            .mac(alg as u8, key, input, out)
            .map_err(|_| Error::Crypto)
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.crypto.random(out).map_err(|_| Error::Crypto)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.memory.wipe(bytes);
    }
}
impl Store<'_> {
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.located = None;
        self.storage
            .replace(Record::OathRecords, FILE_HEADER)
            .map_err(io)
    }
    pub fn install(&mut self) -> Result<(), Error> {
        self.located = None;
        self.size()?;
        let mut bytes = [0; FILE_HEADER.len()];
        self.storage
            .read_at(Record::OathRecords, 0, &mut bytes)
            .map_err(io)?;
        if &bytes != FILE_HEADER {
            return Err(Error::Storage);
        }
        Ok(())
    }
    fn size(&mut self) -> Result<u32, Error> {
        let size = match self.storage.size(Record::OathRecords) {
            Ok(size) => size,
            Err(StorageError::Missing) => return Err(Error::Missing),
            Err(_) => return Err(Error::Storage),
        };
        if size < FILE_HEADER_BYTES || (size - FILE_HEADER_BYTES) % ENTRY_BYTES != 0 {
            return Err(Error::Storage);
        }
        Ok(size)
    }
    /// Entry at a byte offset; zero starts an iteration after the file header.
    pub fn at(&mut self, offset: u32) -> Result<Option<(CredentialId, u32)>, Error> {
        let mut offset = offset.max(FILE_HEADER_BYTES);
        while let Some(entry) = self.read_entry(offset)? {
            if entry.header[0] != 0 {
                return Ok(Some((entry.id, entry.end)));
            }
            offset = entry.end;
        }
        Ok(None)
    }
    fn read_entry(&mut self, offset: u32) -> Result<Option<Entry>, Error> {
        self.located = None;
        let size = self.size()?;
        if offset == size {
            return Ok(None);
        }
        if offset < FILE_HEADER_BYTES
            || offset > size
            || (offset - FILE_HEADER_BYTES) % ENTRY_BYTES != 0
        {
            return Err(Error::Storage);
        }
        let mut header = [0; ENTRY_HEADER_BYTES];
        self.storage
            .read_at(Record::OathRecords, offset, &mut header)
            .map_err(io)?;
        let id = CredentialId(u32::from_be_bytes(header[..ID_BYTES].try_into().unwrap()));
        if id.0 == 0 {
            return Err(Error::Storage);
        }
        // Version zero is a tombstone. Its ID survives deletion and slot reuse
        // always assigns a larger ID, so stale PASS references cannot alias.
        if header[ID_BYTES] != 0 {
            codec::length(&header[ID_BYTES..]).map_err(|_| Error::Storage)?;
        }
        let entry = Entry {
            id,
            offset,
            end: offset + ENTRY_BYTES,
            header: header[ID_BYTES..].try_into().unwrap(),
        };
        self.located = Some(entry);
        Ok(Some(entry))
    }
    fn locate(&mut self, id: CredentialId) -> Result<Entry, Error> {
        if let Some(entry) = self.located
            && entry.id == id
            && entry.header[0] != 0
        {
            return Ok(entry);
        }
        let mut offset = FILE_HEADER_BYTES;
        while let Some(entry) = self.read_entry(offset)? {
            if entry.id == id && entry.header[0] != 0 {
                return Ok(entry);
            }
            offset = entry.end;
        }
        Err(Error::Missing)
    }
    pub(crate) fn credential_kind(
        &mut self,
        id: CredentialId,
    ) -> Result<super::credential::Kind, Error> {
        self.metadata(id).map(|header| header.kind)
    }
    pub(super) fn metadata(&mut self, id: CredentialId) -> Result<codec::Header, Error> {
        let entry = self.locate(id)?;
        codec::fields(&entry.header)
    }
    // One slot is one atomic patch; no record shifting or second ID commit.
    fn write(
        &mut self,
        offset: u32,
        id: CredentialId,
        value: Option<&Credential>,
    ) -> Result<(), Error> {
        self.located = None;
        let mut bytes = [0; ENTRY_BYTES as usize];
        bytes[..ID_BYTES].copy_from_slice(&id.0.to_be_bytes());
        if let Some(value) = value {
            codec::encode(value, (&mut bytes[ID_BYTES..]).try_into().unwrap());
        }
        let result = self
            .storage
            .replace_at(Record::OathRecords, offset, &bytes)
            .map_err(io);
        self.memory.wipe(&mut bytes);
        result
    }
}
impl Repository for Store<'_> {
    fn first(&mut self) -> Result<Option<CredentialId>, Error> {
        Ok(self.at(0)?.map(|(id, _)| id))
    }
    fn next(&mut self, id: CredentialId) -> Result<Option<CredentialId>, Error> {
        let entry = self.locate(id)?;
        Ok(self.at(entry.end)?.map(|(id, _)| id))
    }
    fn matches_name(
        &mut self,
        id: CredentialId,
        name: &[u8],
        _: &mut (impl Crypto + ?Sized),
    ) -> Result<bool, Error> {
        let entry = self.locate(id)?;
        let h = codec::fields(&entry.header)?;
        let mut bytes = [0; codec::NAME_LIMIT];
        let bytes = &mut bytes[..usize::from(h.name_len)];
        self.storage
            .read_at(
                Record::OathRecords,
                entry.offset + ENTRY_HEADER_BYTES as u32,
                bytes,
            )
            .map_err(io)?;
        Ok(bytes == name)
    }
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error> {
        let entry = self.locate(id)?;
        let mut bytes = [0; codec::LENGTH];
        let result = self
            .storage
            .read_at(
                Record::OathRecords,
                entry.offset + ID_BYTES as u32,
                &mut bytes,
            )
            .map_err(io)
            .and_then(|()| codec::validate(&bytes));
        let result = result.map(|()| Credential { bytes });
        // A Rust move may lower to a stack copy. Erase the read buffer on both
        // paths, even when the returned credential uses the same encoding.
        self.memory.wipe(&mut bytes);
        result
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let size = self.size()?;
        let mut vacant = size;
        let mut maximum = 0;
        let mut offset = FILE_HEADER_BYTES;
        while let Some(entry) = self.read_entry(offset)? {
            maximum = maximum.max(entry.id.0);
            if entry.header[0] == 0 && vacant == size {
                vacant = entry.offset;
            }
            offset = entry.end;
        }
        if vacant == size
            && !self
                .storage
                .has_space(
                    PROJECTED_GROWTH_PAGES * STORAGE_PAGE_BYTES,
                    update_reserve(size),
                )
                .map_err(io)?
        {
            return Err(Error::NoSpace);
        }
        let id = CredentialId(maximum.checked_add(1).ok_or(Error::NoSpace)?);
        self.write(vacant, id, Some(value))?;
        Ok(id)
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        let entry = self.locate(id)?;
        self.write(entry.offset, id, Some(value))
    }
    fn update_counter(&mut self, id: CredentialId, counter: &[u8; 8]) -> Result<(), Error> {
        let entry = self.locate(id)?;
        self.located = None;
        self.storage
            .replace_at(
                Record::OathRecords,
                entry.end - codec::COUNTER_BYTES as u32,
                counter,
            )
            .map_err(io)
    }
    fn delete(&mut self, id: CredentialId) -> Result<(), Error> {
        let entry = self.locate(id)?;
        self.write(entry.offset, id, None)
    }
}
impl auth::Repository for Store<'_> {
    fn load(&mut self) -> Result<Option<auth::Metadata>, Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        let result = match self.storage.load(Record::OathMetadata, &mut bytes) {
            Err(StorageError::Missing) => Ok(None),
            Ok(n) => auth::Metadata::decode(&bytes[..n]).map(Some),
            Err(_) => Err(Error::Storage),
        };
        self.memory.wipe(&mut bytes);
        result
    }
    fn replace(&mut self, value: &auth::Metadata) -> Result<(), Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        let n = value.encode(&mut bytes);
        let result = self
            .storage
            .replace(Record::OathMetadata, &bytes[..n])
            .map_err(io);
        self.memory.wipe(&mut bytes);
        result
    }
}

/// Reset persistent OATH state; the caller first removes PASS bindings.
#[cfg(feature = "admin")]
pub fn reset(
    storage: &mut crate::ports::StoragePort<'_>,
    crypto: &mut CryptoPort<'_>,
    memory: &crate::ports::MemoryPort<'_>,
) -> Result<(), Error> {
    storage
        .replace(Record::OathRecords, FILE_HEADER)
        .map_err(io)?;
    let mut mac = Mac::new(crypto, memory);
    let metadata = auth::Metadata::new(&mut mac)?;
    auth::Repository::replace(&mut Store::new(storage, memory), &metadata)
}

#[cfg(all(
    test,
    any(not(feature = "static-backend"), feature = "dynamic-backend")
))]
mod tests;
