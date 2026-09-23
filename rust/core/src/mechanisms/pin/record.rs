// SPDX-License-Identifier: Apache-2.0
//! Existing version-1, 68-byte credential format used by ADMIN and OpenPGP.
use super::{Charge, Credential, Error};
#[cfg(feature = "admin")]
use crate::ports::StorageError;
use crate::{Platform, ports::Record};
const SIZE: usize = 68;

pub(crate) struct RecordPin {
    pub id: Record,
    pub stored_min: u8,
    pub fixed_limit: Option<u8>,
}
impl RecordPin {
    fn valid(&self, b: &[u8; SIZE]) -> Result<(), Error> {
        if b[0] != 1
            || !(self.stored_min..=64).contains(&b[1])
            || b[3] == 0
            || b[2] > b[3]
            || self.fixed_limit.is_some_and(|limit| b[3] != limit)
        {
            return Err(Error::Persistence);
        }
        Ok(())
    }
    fn load(&self, b: &mut [u8; SIZE], p: &mut Platform<'_>) -> Result<(), Error> {
        if p.storage.load(self.id, b).map_err(|_| Error::Persistence)? != SIZE {
            return Err(Error::Persistence);
        }
        self.valid(b)
    }
    fn with_record<T>(
        &self,
        p: &mut Platform<'_>,
        f: impl FnOnce(&mut [u8; SIZE], &mut Platform<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut b = [0; SIZE];
        let result = self.load(&mut b, p).and_then(|()| f(&mut b, p));
        p.memory.wipe(&mut b);
        result
    }
    pub(crate) fn create(
        &self,
        value: &[u8],
        limit: u8,
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        if !(self.stored_min as usize..=64).contains(&value.len()) {
            return Err(Error::Length);
        }
        if limit == 0 || self.fixed_limit.is_some_and(|n| n != limit) {
            return Err(Error::Persistence);
        }
        let mut b = [0; SIZE];
        b[..4].copy_from_slice(&[
            1,
            value.len() as u8,
            if value.is_empty() { 0 } else { limit },
            limit,
        ]);
        b[4..4 + value.len()].copy_from_slice(value);
        let result = p
            .storage
            .replace(self.id, &b)
            .map_err(|_| Error::Persistence);
        p.memory.wipe(&mut b);
        result
    }
    #[cfg(feature = "admin")]
    pub(crate) fn install(
        &self,
        default: &[u8],
        limit: u8,
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        let mut b = [0; SIZE];
        let result = match p.storage.load(self.id, &mut b) {
            Err(StorageError::Missing) => self.create(default, limit, p),
            Ok(SIZE) => self.valid(&b),
            _ => Err(Error::Persistence),
        };
        p.memory.wipe(&mut b);
        result
    }
    pub(crate) fn info(&self, p: &mut Platform<'_>) -> Result<(usize, u8, u8), Error> {
        self.with_record(p, |b, _| Ok((b[1] as usize, b[2], b[3])))
    }
    pub(crate) fn verify(
        &self,
        input: &[u8],
        min: usize,
        charge: Charge,
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        self.with_record(p, |b, p| {
            // OpenPGP checks blocking before input length; ADMIN prechecks length.
            if b[2] == 0 {
                return Err(Error::Blocked);
            }
            if !(min..=64).contains(&input.len()) {
                return Err(Error::Length);
            }
            let length = b[1] as usize;
            let limit = b[3];
            Credential::new(b, 4..4 + length, 2, limit)?.verify(input, charge, &mut |bytes| {
                p.storage
                    .replace(self.id, bytes)
                    .map_err(|_| Error::Persistence)
            })
        })
    }
    pub(crate) fn change(
        &self,
        value: &[u8],
        min: usize,
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        if !(min..=64).contains(&value.len()) {
            return Err(Error::Length);
        }
        let (_, _, limit) = self.info(p)?;
        self.create(value, limit, p)
    }
    #[cfg(feature = "openpgp")]
    pub(crate) fn retry_limit(&self, limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
        if limit == 0 || self.fixed_limit.is_some_and(|n| n != limit) {
            return Err(Error::Persistence);
        }
        self.with_record(p, |b, p| {
            b[3] = limit;
            b[2] = if b[1] == 0 { 0 } else { limit };
            p.storage
                .replace(self.id, b)
                .map_err(|_| Error::Persistence)
        })
    }
}
