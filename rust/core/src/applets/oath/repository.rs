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
const FREE_SPACE_RESERVE: u32 = 64 * 1024;
// The first four bytes store the next credential ID, even when no entries remain.
const NEXT_ID_BYTES: u32 = ID_BYTES as u32;
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
            .replace(Record::OathRecords, &1u32.to_be_bytes())
            .map_err(io)
    }
    pub fn install(&mut self) -> Result<(), Error> {
        match self.storage.size(Record::OathRecords) {
            Ok(n) if n >= NEXT_ID_BYTES => self.next_id().map(|_| ()),
            Err(StorageError::Missing) => Err(Error::Missing),
            _ => Err(Error::Storage),
        }
    }
    fn next_id(&mut self) -> Result<u32, Error> {
        let mut bytes = [0; ID_BYTES];
        self.storage
            .read_at(Record::OathRecords, 0, &mut bytes)
            .map_err(io)?;
        let id = u32::from_be_bytes(bytes);
        if id == 0 {
            return Err(Error::Storage);
        }
        Ok(id)
    }
    /// Entry at a byte offset; zero starts an iteration after the file header.
    pub fn at(&mut self, offset: u32) -> Result<Option<(CredentialId, u32)>, Error> {
        Ok(self.read_entry(offset)?.map(|entry| (entry.id, entry.end)))
    }
    fn read_entry(&mut self, offset: u32) -> Result<Option<Entry>, Error> {
        self.located = None;
        let offset = offset.max(NEXT_ID_BYTES);
        let size = self.storage.size(Record::OathRecords).map_err(io)?;
        if offset == size {
            return Ok(None);
        }
        if offset > size || size - offset < ENTRY_HEADER_BYTES as u32 {
            return Err(Error::Storage);
        }
        let mut header = [0; ENTRY_HEADER_BYTES];
        self.storage
            .read_at(Record::OathRecords, offset, &mut header)
            .map_err(io)?;
        let id = CredentialId(u32::from_be_bytes(header[..ID_BYTES].try_into().unwrap()));
        let length = ID_BYTES as u32
            + codec::length(&header[ID_BYTES..]).map_err(|_| Error::Storage)? as u32;
        if id.0 == 0 || length > size - offset {
            return Err(Error::Storage);
        }
        let entry = Entry {
            id,
            offset,
            end: offset + length,
        };
        self.located = Some(entry);
        Ok(Some(entry))
    }
    fn locate(&mut self, id: CredentialId) -> Result<Entry, Error> {
        if let Some(entry) = self.located
            && entry.id == id
        {
            return Ok(entry);
        }
        let mut offset = NEXT_ID_BYTES;
        while let Some(entry) = self.read_entry(offset)? {
            if entry.id == id {
                return Ok(entry);
            }
            offset = entry.end;
        }
        Err(Error::Missing)
    }
    // Rewrite only live entries into one atomic replacement. No fixed slots or tombstones.
    fn write(
        &mut self,
        offset: u32,
        end: u32,
        id: CredentialId,
        value: Option<&Credential>,
        next_id: u32,
    ) -> Result<(), Error> {
        self.located = None;
        let size = self.storage.size(Record::OathRecords).map_err(io)?;
        let mut bytes = [0; codec::LENGTH];
        let result = (|| {
            self.storage.stage_begin().map_err(io)?;
            self.storage
                .stage_append(&next_id.to_be_bytes())
                .map_err(io)?;
            crate::ports::copy_to_stage(
                self.storage,
                self.memory,
                Record::OathRecords,
                NEXT_ID_BYTES,
                offset - NEXT_ID_BYTES,
            )
            .map_err(io)?;
            if let Some(value) = value {
                let n = codec::encode(value, &mut bytes);
                self.storage.stage_append(&id.0.to_be_bytes()).map_err(io)?;
                self.storage.stage_append(&bytes[..n]).map_err(io)?;
            }
            crate::ports::copy_to_stage(
                self.storage,
                self.memory,
                Record::OathRecords,
                end,
                size - end,
            )
            .map_err(io)?;
            self.storage.stage_commit(Record::OathRecords).map_err(io)
        })();
        self.memory.wipe(&mut bytes);
        if result.is_err() {
            self.storage.stage_abort();
        }
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
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error> {
        let entry = self.locate(id)?;
        let mut bytes = [0; codec::LENGTH];
        let n = (entry.end - entry.offset - ID_BYTES as u32) as usize;
        let result = self
            .storage
            .read_at(
                Record::OathRecords,
                entry.offset + ID_BYTES as u32,
                &mut bytes[..n],
            )
            .map_err(io)
            .and_then(|()| codec::decode(&bytes[..n]));
        self.memory.wipe(&mut bytes);
        result
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let size = self.storage.size(Record::OathRecords).map_err(io)?;
        let needed =
            (ID_BYTES + codec::FIXED_BYTES + value.name().len() + value.key().len()) as u32;
        if !self
            .storage
            .has_space(needed, FREE_SPACE_RESERVE)
            .map_err(io)?
        {
            return Err(Error::NoSpace);
        }
        let id = CredentialId(self.next_id()?);
        let next = id.0.checked_add(1).ok_or(Error::NoSpace)?;
        self.write(size, size, id, Some(value), next)?;
        Ok(id)
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        let entry = self.locate(id)?;
        let next = self.next_id()?;
        self.write(entry.offset, entry.end, id, Some(value), next)
    }
    fn delete(&mut self, id: CredentialId) -> Result<(), Error> {
        let entry = self.locate(id)?;
        let next = self.next_id()?;
        self.write(entry.offset, entry.end, id, None, next)
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
        .replace(Record::OathRecords, &1u32.to_be_bytes())
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
