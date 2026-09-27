// SPDX-License-Identifier: Apache-2.0
use super::{
    Crypto, Error, auth,
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
    fn matches_name(
        &mut self,
        id: CredentialId,
        name: &[u8],
        crypto: &mut (impl Crypto + ?Sized),
    ) -> Result<bool, Error> {
        let mut record = self.load(id)?;
        let found = record.name() == name;
        record.clear(crypto);
        Ok(found)
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error>;
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error>;
    fn delete(&mut self, id: CredentialId) -> Result<(), Error>;
    fn update_counter(&mut self, id: CredentialId, counter: &[u8; 8]) -> Result<(), Error>;
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
    // RFC 4226 dynamic truncation: the last digest nibble selects four bytes;
    // clear the sign bit to obtain a 31-bit integer. Decimal formatting and
    // reduction to the configured digit count happen at the output boundary.
    pub fn truncated(&self) -> u32 {
        let offset = usize::from(self.bytes[self.length - 1] & 15);
        u32::from_be_bytes(self.bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff
    }
    pub fn clear(&mut self, crypto: &mut (impl Crypto + ?Sized)) {
        crypto.wipe(&mut self.bytes);
    }
}
pub fn find(
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
    name: &[u8],
) -> Result<CredentialId, Error> {
    let mut cursor = repository.first()?;
    while let Some(id) = cursor {
        if repository.matches_name(id, name, crypto)? {
            return Ok(id);
        }
        cursor = repository.next(id)?;
    }
    Err(Error::Missing)
}
pub fn put(
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
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
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
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
        .rename(new, crypto)
        .and_then(|()| repository.replace(id, &record));
    record.clear(crypto);
    result
}
/// Counter update precedes calculation, exactly as in C oath_calculate.
/// Call only after the adapter has checked its session's OATH access grant.
pub fn calculate(
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
    id: CredentialId,
    challenge: &[u8],
    presence: Presence,
) -> Result<Digest, Error> {
    let mut record = repository.load(id)?;
    let result = calculate_loaded(repository, crypto, id, &record, challenge, presence);
    record.clear(crypto);
    result
}
/// The caller owns the loaded key and must clear it on success and failure.
#[inline(never)]
pub(super) fn calculate_loaded(
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
    id: CredentialId,
    record: &Credential,
    challenge: &[u8],
    presence: Presence,
) -> Result<Digest, Error> {
    if record.properties().touch() && matches!(presence, Presence::NotConfirmed) {
        return Err(Error::PresenceRequired);
    }
    let counter;
    let message = match record.kind() {
        Kind::Hotp => {
            let value = u64::from_be_bytes(record.moving_factor())
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?;
            counter = value.to_be_bytes();
            repository.update_counter(id, &counter)?;
            &counter[..]
        }
        Kind::Totp => {
            if challenge.is_empty() || challenge.len() > auth::CHALLENGE_BYTES {
                return Err(Error::Invalid);
            }
            if record.properties().increasing() {
                if challenge.len() != auth::CHALLENGE_BYTES
                    || challenge < &record.moving_factor()[..]
                {
                    return Err(Error::IncreasingChallenge);
                }
                repository.update_counter(id, challenge.try_into().map_err(|_| Error::Invalid)?)?;
            }
            challenge
        }
    };
    let mut digest = Digest {
        digits: record.digits(),
        bytes: [0; 64],
        length: record.algorithm().digest_length(),
    };
    if let Err(error) = crypto.hmac(record.algorithm(), record.key(), message, &mut digest.bytes) {
        digest.clear(crypto);
        return Err(error);
    }
    Ok(digest)
}
