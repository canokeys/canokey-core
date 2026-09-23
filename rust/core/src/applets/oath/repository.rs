// SPDX-License-Identifier: Apache-2.0
//! Safe assembly adapters. Each backend borrow ends before the next service call.
#![forbid(unsafe_code)]
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth, codec,
    credential::Credential,
    service::{CredentialId, Repository},
};
use crate::ports::{Crypto as CryptoPort, Memory, Record, Storage, StorageError};
pub struct Store<'a> {
    storage: &'a mut dyn Storage,
    memory: &'a dyn Memory,
    located: Option<(CredentialId, u32)>,
}
pub struct Mac<'a> {
    crypto: &'a mut dyn CryptoPort,
    memory: &'a dyn Memory,
}
impl<'a> Store<'a> {
    pub fn new(storage: &'a mut dyn Storage, memory: &'a dyn Memory) -> Self {
        Self {
            storage,
            memory,
            located: None,
        }
    }
}
impl<'a> Mac<'a> {
    pub fn new(crypto: &'a mut dyn CryptoPort, memory: &'a dyn Memory) -> Self {
        Self { crypto, memory }
    }
}
const HEADER: u32 = 4; // Next credential ID, retained even when the last entry is deleted.
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
        self.storage
            .replace(Record::OathRecords, &1u32.to_be_bytes())
            .map_err(io)
    }
    pub fn install(&mut self) -> Result<(), Error> {
        match self.storage.size(Record::OathRecords) {
            Ok(n) if n >= HEADER => self.next_id().map(|_| ()),
            Err(StorageError::Missing) => Err(Error::Missing),
            _ => Err(Error::Storage),
        }
    }
    fn next_id(&mut self) -> Result<u32, Error> {
        let mut bytes = [0; 4];
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
        let offset = offset.max(HEADER);
        let size = self.storage.size(Record::OathRecords).map_err(io)?;
        if offset == size {
            return Ok(None);
        }
        if offset > size || size - offset < 10 {
            return Err(Error::Storage);
        }
        let mut header = [0; 10];
        self.storage
            .read_at(Record::OathRecords, offset, &mut header)
            .map_err(io)?;
        let id = CredentialId(u32::from_be_bytes(header[..4].try_into().unwrap()));
        let length = 4 + codec::length(&header[4..]).map_err(|_| Error::Storage)? as u32;
        if id.0 == 0 || length > size - offset {
            return Err(Error::Storage);
        }
        self.located = Some((id, offset));
        Ok(Some((id, offset + length)))
    }
    fn locate(&mut self, id: CredentialId) -> Result<u32, Error> {
        if let Some((cached, offset)) = self.located
            && cached == id
        {
            return Ok(offset);
        }
        let mut offset = HEADER;
        while let Some((current, next)) = self.at(offset)? {
            if current == id {
                return Ok(offset);
            }
            offset = next;
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
                HEADER,
                offset - HEADER,
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
        let offset = self.locate(id)?;
        let (_, end) = self.at(offset)?.ok_or(Error::Missing)?;
        Ok(self.at(end)?.map(|(id, _)| id))
    }
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error> {
        let offset = self.locate(id)?;
        let (_, end) = self.at(offset)?.ok_or(Error::Missing)?;
        let mut bytes = [0; codec::LENGTH];
        let n = (end - offset - 4) as usize;
        let result = self
            .storage
            .read_at(Record::OathRecords, offset + 4, &mut bytes[..n])
            .map_err(io)
            .and_then(|()| codec::decode(&bytes[..n]));
        self.memory.wipe(&mut bytes);
        result
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let size = self.storage.size(Record::OathRecords).map_err(io)?;
        let needed = (18 + value.name().len() + value.key().len()) as u32;
        if !self.storage.has_space(needed, 128 * 512).map_err(io)? {
            return Err(Error::NoSpace);
        }
        let id = CredentialId(self.next_id()?);
        let next = id.0.checked_add(1).ok_or(Error::NoSpace)?;
        self.write(size, size, id, Some(value), next)?;
        Ok(id)
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        let offset = self.locate(id)?;
        let (_, end) = self.at(offset)?.ok_or(Error::Missing)?;
        let next = self.next_id()?;
        self.write(offset, end, id, Some(value), next)
    }
    fn delete(&mut self, id: CredentialId) -> Result<(), Error> {
        let offset = self.locate(id)?;
        let (_, end) = self.at(offset)?.ok_or(Error::Missing)?;
        let next = self.next_id()?;
        self.write(offset, end, id, None, next)
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
    storage: &mut dyn Storage,
    crypto: &mut dyn CryptoPort,
    memory: &dyn Memory,
) -> Result<(), Error> {
    storage
        .replace(Record::OathRecords, &1u32.to_be_bytes())
        .map_err(io)?;
    let mut mac = Mac::new(crypto, memory);
    let metadata = auth::Metadata::new(&mut mac)?;
    auth::Repository::replace(&mut Store::new(storage, memory), &metadata)
}
