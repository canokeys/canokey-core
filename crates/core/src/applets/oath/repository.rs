// SPDX-License-Identifier: Apache-2.0
//! Safe assembly adapters. Each backend borrow ends before the next service call.
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth, codec,
    credential::Credential,
    service::{CredentialId, Repository},
};
use crate::ports::{Crypto as BackendCrypto, Memory, Record, Storage, StorageError};
pub struct Store<'a, S: Storage + ?Sized, M: Memory + ?Sized> {
    storage: &'a mut S,
    memory: &'a M,
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
pub struct Mac<'a, C: BackendCrypto + ?Sized, M: Memory + ?Sized> {
    crypto: &'a mut C,
    memory: &'a M,
}
impl<'a, S: Storage + ?Sized, M: Memory + ?Sized> Store<'a, S, M> {
    pub fn new(storage: &'a mut S, memory: &'a M) -> Self {
        Self {
            storage,
            memory,
            located: None,
        }
    }
}
impl<'a, C: BackendCrypto + ?Sized, M: Memory + ?Sized> Mac<'a, C, M> {
    pub fn new(crypto: &'a mut C, memory: &'a M) -> Self {
        Self { crypto, memory }
    }
}
const ID_BYTES: usize = 4;
const ENTRY_HEADER_BYTES: usize = ID_BYTES + codec::HEADER_BYTES;
// Largest stored entry: ID plus a credential with maximum name and key.
const MAX_ENTRY_BYTES: u32 = (ID_BYTES + codec::LENGTH) as u32;
const STORAGE_PAGE_BYTES: u32 = 512;
// Measured 204-page CIU policy: metadata compaction margin above the projected
// OATH file copy, with a 20 KiB floor for the primary mixed workload.
const METADATA_MARGIN_PAGES: u32 = 8;
const MIN_UPDATE_RESERVE_BYTES: u32 = 20 * 1024;
// Conservative durable growth for appending an entry, including a CTZ page.
const PROJECTED_GROWTH_PAGES: u32 = 2;
// Bounded stack chunk for copying entries into a staged replacement file.
const COPY_CHUNK_BYTES: usize = 256;
// OATH-local admission margin, not a reservation enforced by other applets.
// Deletion and renaming stage a full copy, and a counter patch near the
// beginning copies the surviving CTZ tail; both need about the file size.
fn update_reserve(size: u32) -> u32 {
    let pages = (size + MAX_ENTRY_BYTES).div_ceil(STORAGE_PAGE_BYTES);
    ((pages + METADATA_MARGIN_PAGES) * STORAGE_PAGE_BYTES).max(MIN_UPDATE_RESERVE_BYTES)
}
// File layout: magic, then a big-endian lower bound for the next credential ID,
// then packed entries (ID4, header6, name, key, counter8) with no padding.
// Every ID ever assigned is below max(next, largest live ID + 1), so deleted
// IDs, including PASS references to them, never alias a new credential.
const FILE_MAGIC: &[u8; 4] = b"OAT3";
const NEXT_ID: u32 = FILE_MAGIC.len() as u32;
const FILE_HEADER_BYTES: u32 = NEXT_ID + ID_BYTES as u32;
fn io(_: StorageError) -> Error {
    Error::Storage
}
impl<C: BackendCrypto + ?Sized, M: Memory + ?Sized> Crypto for Mac<'_, C, M> {
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
impl<S: Storage + ?Sized, M: Memory + ?Sized> Store<'_, S, M> {
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.located = None;
        self.storage
            .replace(Record::OathRecords, &empty_file())
            .map_err(io)
    }
    pub fn install(&mut self) -> Result<(), Error> {
        self.located = None;
        self.next_id().map(|_| ())
    }
    fn size(&mut self) -> Result<u32, Error> {
        let size = match self.storage.size(Record::OathRecords) {
            Ok(size) => size,
            Err(StorageError::Missing) => return Err(Error::Missing),
            Err(_) => return Err(Error::Storage),
        };
        if size < FILE_HEADER_BYTES {
            return Err(Error::Storage);
        }
        Ok(size)
    }
    /// Validate the file header and return its stored next-ID lower bound.
    fn next_id(&mut self) -> Result<u32, Error> {
        self.size()?;
        let mut bytes = [0; FILE_HEADER_BYTES as usize];
        self.storage
            .read_at(Record::OathRecords, 0, &mut bytes)
            .map_err(io)?;
        if &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(Error::Storage);
        }
        let next = u32::from_be_bytes(bytes[FILE_MAGIC.len()..].try_into().unwrap());
        if next == 0 {
            return Err(Error::Storage);
        }
        Ok(next)
    }
    /// Entry at a byte offset; zero starts an iteration after the file header.
    pub fn at(&mut self, offset: u32) -> Result<Option<(CredentialId, u32)>, Error> {
        Ok(self
            .read_entry(offset.max(FILE_HEADER_BYTES))?
            .map(|entry| (entry.id, entry.end)))
    }
    fn read_entry(&mut self, offset: u32) -> Result<Option<Entry>, Error> {
        self.located = None;
        let size = self.size()?;
        if offset == size {
            return Ok(None);
        }
        if offset < FILE_HEADER_BYTES || offset > size {
            return Err(Error::Storage);
        }
        let mut header = [0; ENTRY_HEADER_BYTES];
        self.storage
            .read_at(Record::OathRecords, offset, &mut header)
            .map_err(io)?;
        let id = CredentialId(u32::from_be_bytes(header[..ID_BYTES].try_into().unwrap()));
        let length = codec::stored_length(&header[ID_BYTES..]).map_err(|_| Error::Storage)?;
        let end = offset + (ID_BYTES + length) as u32;
        if id.0 == 0 || end > size {
            return Err(Error::Storage);
        }
        let entry = Entry {
            id,
            offset,
            end,
            header: header[ID_BYTES..].try_into().unwrap(),
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
        let mut offset = FILE_HEADER_BYTES;
        while let Some(entry) = self.read_entry(offset)? {
            if entry.id == id {
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
    /// Publish a complete copy with the entry replaced or removed. Entries
    /// change length, so this is one atomic staged rename, never a shift.
    fn rewrite(&mut self, id: CredentialId, value: Option<&Credential>) -> Result<(), Error> {
        let next = self.next_id()?;
        let size = self.size()?;
        let entry = self.locate(id)?;
        self.located = None;
        let mut header = empty_file();
        header[NEXT_ID as usize..].copy_from_slice(&next.max(id.0.saturating_add(1)).to_be_bytes());
        let mut chunk = [0; COPY_CHUNK_BYTES];
        let mut bytes = [0; MAX_ENTRY_BYTES as usize];
        let length = value.map_or(0, |value| encode(id, value, &mut bytes));
        let result = (|| {
            self.storage.stage_begin()?;
            self.storage.stage_append(&header)?;
            for (mut from, to) in [(FILE_HEADER_BYTES, entry.offset), (entry.end, size)] {
                if from == entry.end && length != 0 {
                    self.storage.stage_append(&bytes[..length])?;
                }
                while from < to {
                    let n = (to - from).min(COPY_CHUNK_BYTES as u32) as usize;
                    self.storage
                        .read_at(Record::OathRecords, from, &mut chunk[..n])?;
                    self.storage.stage_append(&chunk[..n])?;
                    from += n as u32;
                }
            }
            self.storage.stage_commit(Record::OathRecords)
        })();
        if result.is_err() {
            self.storage.stage_abort();
        }
        self.memory.wipe(&mut chunk);
        self.memory.wipe(&mut bytes);
        result.map_err(io)
    }
}
fn empty_file() -> [u8; FILE_HEADER_BYTES as usize] {
    let mut bytes = [0; FILE_HEADER_BYTES as usize];
    bytes[..FILE_MAGIC.len()].copy_from_slice(FILE_MAGIC);
    bytes[NEXT_ID as usize..].copy_from_slice(&1u32.to_be_bytes());
    bytes
}
fn encode(id: CredentialId, value: &Credential, out: &mut [u8; MAX_ENTRY_BYTES as usize]) -> usize {
    out[..ID_BYTES].copy_from_slice(&id.0.to_be_bytes());
    ID_BYTES + codec::encode(value, (&mut out[ID_BYTES..]).try_into().unwrap())
}
impl<S: Storage + ?Sized, M: Memory + ?Sized> Repository for Store<'_, S, M> {
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
    fn load_into(&mut self, id: CredentialId, out: &mut Credential) -> Result<(), Error> {
        // Read in place: no intermediate stack copy of the key exists. The
        // packed name and key expand into the zero-padded RAM view.
        out.bytes.fill(0);
        let result = self.locate(id).and_then(|entry| {
            let name = codec::HEADER_BYTES + usize::from(entry.header[codec::NAME_LENGTH]);
            let key = usize::from(entry.header[codec::KEY_LENGTH]);
            let at = entry.offset + ID_BYTES as u32;
            let key_at = at + name as u32;
            let counter_at = key_at + key as u32;
            let b = &mut out.bytes;
            self.storage
                .read_at(Record::OathRecords, at, &mut b[..name])
                .and_then(|()| {
                    self.storage.read_at(
                        Record::OathRecords,
                        key_at,
                        &mut b[codec::KEY_OFFSET..codec::KEY_OFFSET + key],
                    )
                })
                .and_then(|()| {
                    self.storage.read_at(
                        Record::OathRecords,
                        counter_at,
                        &mut b[codec::COUNTER_OFFSET..],
                    )
                })
                .map_err(io)
                .and_then(|()| codec::validate(&out.bytes))
        });
        if result.is_err() {
            self.memory.wipe(&mut out.bytes);
        }
        result
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let mut next = self.next_id()?;
        let size = self.size()?;
        let mut offset = FILE_HEADER_BYTES;
        while let Some(entry) = self.read_entry(offset)? {
            next = next.max(entry.id.0.checked_add(1).ok_or(Error::NoSpace)?);
            offset = entry.end;
        }
        if !self
            .storage
            .has_space(
                PROJECTED_GROWTH_PAGES * STORAGE_PAGE_BYTES,
                update_reserve(size),
            )
            .map_err(io)?
        {
            return Err(Error::NoSpace);
        }
        // u32::MAX is never assigned, so `id + 1` always bounds deleted IDs.
        if next == u32::MAX {
            return Err(Error::NoSpace);
        }
        let id = CredentialId(next);
        self.located = None;
        let mut bytes = [0; MAX_ENTRY_BYTES as usize];
        let length = encode(id, value, &mut bytes);
        // Appending one entry is a single atomic patch at the end of the file.
        let result = self
            .storage
            .replace_at(Record::OathRecords, size, &bytes[..length])
            .map_err(io);
        self.memory.wipe(&mut bytes);
        result.map(|()| id)
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        self.rewrite(id, Some(value))
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
        self.rewrite(id, None)
    }
}
impl<S: Storage + ?Sized, M: Memory + ?Sized> auth::Repository for Store<'_, S, M> {
    fn load_into(&mut self, out: &mut auth::Metadata) -> Result<bool, Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        let result = match self.storage.load(Record::OathMetadata, &mut bytes) {
            Err(StorageError::Missing) => Ok(false),
            Ok(n) => out.decode_into(&bytes[..n]).map(|()| true),
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
    storage: &mut (impl Storage + ?Sized),
    crypto: &mut (impl BackendCrypto + ?Sized),
    memory: &(impl Memory + ?Sized),
) -> Result<(), Error> {
    storage
        .replace(Record::OathRecords, &empty_file())
        .map_err(io)?;
    let mut mac = Mac::new(crypto, memory);
    let metadata = auth::Metadata::new(&mut mac)?;
    auth::Repository::replace(&mut Store::new(storage, memory), &metadata)
}

#[cfg(test)]
mod tests;
