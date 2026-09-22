// SPDX-License-Identifier: Apache-2.0
//! Safe assembly adapters. Each backend borrow ends before the next service call.
#![forbid(unsafe_code)]
use crate::services::{Platform, Record, StorageError};
use canokey_oath::{
    Algorithm, Crypto, Error, auth, codec,
    credential::Credential,
    service::{CredentialId, Repository},
};
use core::cell::RefCell;
pub type Shared<'a> = RefCell<&'a mut dyn Platform>;
pub struct Store<'a, 'b>(pub &'a Shared<'b>);
pub struct Mac<'a, 'b>(pub &'a Shared<'b>);
const ENTRY: u32 = 4 + codec::LENGTH as u32;
fn io(_: StorageError) -> Error {
    Error::Storage
}
impl Crypto for Mac<'_, '_> {
    fn hmac(
        &mut self,
        alg: Algorithm,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), Error> {
        self.0
            .borrow_mut()
            .mac(alg as u8, key, input, out)
            .map_err(|_| Error::Crypto)
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0.borrow_mut().random(out).map_err(|_| Error::Crypto)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.0.borrow_mut().wipe(bytes);
    }
}
impl Store<'_, '_> {
    pub fn install(&mut self) -> Result<(), Error> {
        match self.0.borrow_mut().size(Record::OathRecords) {
            Ok(n) if n % ENTRY == 0 => Ok(()),
            Err(StorageError::Missing) => Err(Error::Missing),
            _ => Err(Error::Storage),
        }
    }
    pub fn count(&mut self) -> Result<u32, Error> {
        let n = self.0.borrow_mut().size(Record::OathRecords).map_err(io)?;
        if n % ENTRY != 0 {
            return Err(Error::Storage);
        }
        Ok(n / ENTRY)
    }
    fn header(&mut self, slot: u32) -> Result<(CredentialId, bool), Error> {
        let mut bytes = [0; 5];
        self.0
            .borrow_mut()
            .read_at(Record::OathRecords, slot * ENTRY, &mut bytes)
            .map_err(io)?;
        let id = CredentialId(u32::from_be_bytes(bytes[..4].try_into().unwrap()));
        if id.0 == 0 || bytes[4] > 1 {
            return Err(Error::Storage);
        }
        Ok((id, bytes[4] != 0))
    }
    fn locate(&mut self, id: CredentialId) -> Result<u32, Error> {
        for slot in 0..self.count()? {
            if self.header(slot)? == (id, true) {
                return Ok(slot);
            }
        }
        Err(Error::Missing)
    }
    pub fn at(&mut self, slot: u32) -> Result<Option<CredentialId>, Error> {
        let (id, live) = self.header(slot)?;
        Ok(if live { Some(id) } else { None })
    }
    fn write(
        &mut self,
        slot: u32,
        id: CredentialId,
        value: Option<&Credential>,
    ) -> Result<(), Error> {
        let mut bytes = [0; ENTRY as usize];
        bytes[..4].copy_from_slice(&id.0.to_be_bytes());
        if let Some(value) = value {
            codec::encode(value, (&mut bytes[4..]).try_into().unwrap());
        }
        let result = self
            .0
            .borrow_mut()
            .replace_at(Record::OathRecords, slot * ENTRY, &bytes)
            .map_err(io);
        self.0.borrow_mut().wipe(&mut bytes);
        result
    }
}
impl Repository for Store<'_, '_> {
    fn first(&mut self) -> Result<Option<CredentialId>, Error> {
        for slot in 0..self.count()? {
            if let Some(id) = self.at(slot)? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
    fn next(&mut self, id: CredentialId) -> Result<Option<CredentialId>, Error> {
        for slot in self.locate(id)? + 1..self.count()? {
            if let Some(next) = self.at(slot)? {
                return Ok(Some(next));
            }
        }
        Ok(None)
    }
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error> {
        let slot = self.locate(id)?;
        let mut bytes = [0; codec::LENGTH];
        let result = self
            .0
            .borrow_mut()
            .read_at(Record::OathRecords, slot * ENTRY + 4, &mut bytes)
            .map_err(io)
            .and_then(|()| codec::decode(&bytes));
        self.0.borrow_mut().wipe(&mut bytes);
        result
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let count = self.count()?;
        let mut vacant = count;
        let mut maximum = 0;
        for slot in 0..count {
            let (id, live) = self.header(slot)?;
            maximum = maximum.max(id.0);
            if !live && vacant == count {
                vacant = slot;
            }
        }
        if vacant == count
            && !self
                .0
                .borrow_mut()
                .has_space(ENTRY, 128 * 512)
                .map_err(io)?
        {
            return Err(Error::NoSpace);
        }
        let id = CredentialId(maximum.checked_add(1).ok_or(Error::NoSpace)?);
        self.write(vacant, id, Some(value))?;
        Ok(id)
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        let slot = self.locate(id)?;
        self.write(slot, id, Some(value))
    }
    fn delete(&mut self, id: CredentialId) -> Result<(), Error> {
        let slot = self.locate(id)?;
        self.write(slot, id, None)
    }
}
impl auth::Repository for Store<'_, '_> {
    fn load(&mut self) -> Result<Option<auth::Metadata>, Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        let result = match self.0.borrow_mut().load(Record::OathMetadata, &mut bytes) {
            Err(StorageError::Missing) => Ok(None),
            Ok(auth::METADATA_LENGTH) => auth::Metadata::decode(&bytes).map(Some),
            _ => Err(Error::Storage),
        };
        self.0.borrow_mut().wipe(&mut bytes);
        result
    }
    fn replace(&mut self, value: &auth::Metadata) -> Result<(), Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        value.encode(&mut bytes);
        let result = self
            .0
            .borrow_mut()
            .replace(Record::OathMetadata, &bytes)
            .map_err(io);
        self.0.borrow_mut().wipe(&mut bytes);
        result
    }
}
