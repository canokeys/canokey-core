// SPDX-License-Identifier: Apache-2.0
//! Length-delimited credential record shared by ADMIN and OpenPGP.
use super::{Charge, Credential, Error};
#[cfg(feature = "admin")]
use crate::ports::StorageError;
use crate::{Platform, ports::Record};
const PIN_CAPACITY: usize = 64;
const FORMAT_VERSION: u8 = 1;
const VERSION: usize = 0;
const LENGTH: usize = 1;
const REMAINING: usize = 2;
const RETRY_LIMIT: usize = 3;
const VALUE: usize = 4;
const SIZE: usize = VALUE + PIN_CAPACITY;

/// Public record metadata only; reading it never grants PIN authorization.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PinInfo {
    pub length_bytes: usize,
    pub retries_remaining: u8,
    pub retry_limit: u8,
}

pub(crate) struct RecordPin {
    pub id: Record,
    pub stored_min: u8,
    pub fixed_limit: Option<u8>,
}
impl RecordPin {
    fn valid(&self, b: &[u8; SIZE]) -> Result<(), Error> {
        if b[VERSION] != FORMAT_VERSION
            || !(self.stored_min..=PIN_CAPACITY as u8).contains(&b[LENGTH])
            || b[RETRY_LIMIT] == 0
            || b[REMAINING] > b[RETRY_LIMIT]
            || self
                .fixed_limit
                .is_some_and(|limit| b[RETRY_LIMIT] != limit)
        {
            return Err(Error::Persistence);
        }
        Ok(())
    }
    fn load(&self, b: &mut [u8; SIZE], p: &mut Platform<'_>) -> Result<(), Error> {
        let n = p.storage.load(self.id, b).map_err(|_| Error::Persistence)?;
        if n < VALUE || n != VALUE + b[LENGTH] as usize {
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
        if !(self.stored_min as usize..=PIN_CAPACITY).contains(&value.len()) {
            return Err(Error::Length);
        }
        if limit == 0 || self.fixed_limit.is_some_and(|n| n != limit) {
            return Err(Error::Persistence);
        }
        let mut b = [0; SIZE];
        b[..VALUE].copy_from_slice(&[
            FORMAT_VERSION,
            value.len() as u8,
            if value.is_empty() { 0 } else { limit },
            limit,
        ]);
        b[VALUE..VALUE + value.len()].copy_from_slice(value);
        let result = p
            .storage
            .replace(self.id, &b[..VALUE + value.len()])
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
            Ok(n) if n >= VALUE && n == VALUE + b[LENGTH] as usize => self.valid(&b),
            _ => Err(Error::Persistence),
        };
        p.memory.wipe(&mut b);
        result
    }
    pub(crate) fn info(&self, p: &mut Platform<'_>) -> Result<PinInfo, Error> {
        self.with_record(p, |b, _| {
            Ok(PinInfo {
                length_bytes: b[LENGTH] as usize,
                retries_remaining: b[REMAINING],
                retry_limit: b[RETRY_LIMIT],
            })
        })
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
            if b[REMAINING] == 0 {
                return Err(Error::Blocked);
            }
            if !(min..=PIN_CAPACITY).contains(&input.len()) {
                return Err(Error::Length);
            }
            let length = b[LENGTH] as usize;
            let limit = b[RETRY_LIMIT];
            Credential::new(b, VALUE..VALUE + length, REMAINING, limit)?.verify(
                input,
                charge,
                &mut |bytes| {
                    p.storage
                        .replace(self.id, &bytes[..VALUE + length])
                        .map_err(|_| Error::Persistence)
                },
            )
        })
    }
    pub(crate) fn change(
        &self,
        value: &[u8],
        min: usize,
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        if !(min..=PIN_CAPACITY).contains(&value.len()) {
            return Err(Error::Length);
        }
        let limit = self.info(p)?.retry_limit;
        self.create(value, limit, p)
    }
    #[cfg(feature = "openpgp")]
    pub(crate) fn retry_limit(&self, limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
        if limit == 0 || self.fixed_limit.is_some_and(|n| n != limit) {
            return Err(Error::Persistence);
        }
        self.with_record(p, |b, p| {
            b[RETRY_LIMIT] = limit;
            b[REMAINING] = if b[LENGTH] == 0 { 0 } else { limit };
            p.storage
                .replace(self.id, &b[..VALUE + b[LENGTH] as usize])
                .map_err(|_| Error::Persistence)
        })
    }
}
