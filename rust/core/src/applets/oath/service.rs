// SPDX-License-Identifier: Apache-2.0
use super::{
    Crypto, Error,
    credential::{Credential, Kind},
};
/// Stable repository identity. Deleted identities must never alias new records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialId(pub u32);
/// Serialized storage access. No live file/cache lease may cross crypto or a yield.
/// Mutations commit atomically or return an error; uncertain errors invalidate
/// backend access until reload. Enumeration order matches insertion order.
pub trait Repository {
    fn first(&mut self) -> Result<Option<CredentialId>, Error>;
    fn next(&mut self, id: CredentialId) -> Result<Option<CredentialId>, Error>;
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error>;
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error>;
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error>;
    fn delete(&mut self, id: CredentialId) -> Result<(), Error>;
}
/// Request-bound evidence supplied by the runtime after presence completion.
/// It is never cached on a credential or reused by an applet implicitly.
#[derive(Clone, Copy)]
pub enum Presence {
    NotConfirmed,
    Confirmed,
}
pub struct Digest {
    digits: u8,
    bytes: [u8; 64],
    length: usize,
}
impl Digest {
    pub const fn digits(&self) -> u8 {
        self.digits
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub fn truncated(&self) -> u32 {
        let offset = usize::from(self.bytes[self.length - 1] & 15);
        u32::from_be_bytes(self.bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff
    }
    pub fn clear(&mut self, crypto: &mut dyn Crypto) {
        crypto.wipe(&mut self.bytes);
    }
}
pub fn find(
    repository: &mut dyn Repository,
    crypto: &mut dyn Crypto,
    name: &[u8],
) -> Result<CredentialId, Error> {
    let mut cursor = repository.first()?;
    while let Some(id) = cursor {
        let mut record = repository.load(id)?;
        let found = record.name() == name;
        record.clear(crypto);
        if found {
            return Ok(id);
        }
        cursor = repository.next(id)?;
    }
    Err(Error::Missing)
}
pub fn put(
    repository: &mut dyn Repository,
    crypto: &mut dyn Crypto,
    record: &Credential,
) -> Result<CredentialId, Error> {
    match find(repository, crypto, record.name()) {
        Ok(_) => return Err(Error::Duplicate),
        Err(Error::Missing) => (),
        Err(error) => return Err(error),
    }
    repository.insert(record)
}
pub fn rename(
    repository: &mut dyn Repository,
    crypto: &mut dyn Crypto,
    old: &[u8],
    new: &[u8],
) -> Result<(), Error> {
    let id = find(repository, crypto, old)?;
    match find(repository, crypto, new) {
        Ok(_) => return Err(Error::Duplicate),
        Err(Error::Missing) => (),
        Err(error) => return Err(error),
    }
    let mut record = repository.load(id)?;
    let result = record
        .rename(new)
        .and_then(|()| repository.replace(id, &record));
    record.clear(crypto);
    result
}
/// Counter update precedes calculation, exactly as in C oath_calculate.
/// Call only after the adapter has checked its session's OATH access grant.
pub fn calculate(
    repository: &mut dyn Repository,
    crypto: &mut dyn Crypto,
    id: CredentialId,
    challenge: &[u8],
    presence: Presence,
) -> Result<Digest, Error> {
    let mut record = repository.load(id)?;
    let result = (|| {
        if record.properties.touch() && matches!(presence, Presence::NotConfirmed) {
            return Err(Error::PresenceRequired);
        }
        let counter;
        let message = match record.kind {
            Kind::Hotp => {
                let value = u64::from_be_bytes(record.moving_factor)
                    .checked_add(1)
                    .ok_or(Error::CounterExhausted)?;
                record.moving_factor = value.to_be_bytes();
                repository.replace(id, &record)?;
                counter = record.moving_factor;
                &counter[..]
            }
            Kind::Totp => {
                if challenge.is_empty() || challenge.len() > 8 {
                    return Err(Error::Invalid);
                }
                if record.properties.increasing() {
                    if challenge.len() != 8 || challenge < &record.moving_factor[..] {
                        return Err(Error::IncreasingChallenge);
                    }
                    record.moving_factor.copy_from_slice(challenge);
                    repository.replace(id, &record)?;
                }
                challenge
            }
        };
        let mut digest = Digest {
            digits: record.digits,
            bytes: [0; 64],
            length: record.algorithm.digest_length(),
        };
        if let Err(error) = crypto.hmac(record.algorithm, record.key(), message, &mut digest.bytes)
        {
            digest.clear(crypto);
            return Err(error);
        }
        Ok(digest)
    })();
    record.clear(crypto);
    result
}
