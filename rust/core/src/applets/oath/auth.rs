// SPDX-License-Identifier: Apache-2.0
//! Existing OATH access-code challenge protocol, independent of ADMIN PINs.
use super::{Algorithm, Crypto, Error};
pub const METADATA_LENGTH: usize = 26;
pub struct Metadata {
    handle: [u8; 8],
    key: Option<[u8; 16]>,
}
impl Metadata {
    pub fn new(crypto: &mut dyn Crypto) -> Result<Self, Error> {
        let mut handle = [0; 8];
        crypto.random(&mut handle)?;
        Ok(Self { handle, key: None })
    }
    pub fn encode(&self, out: &mut [u8; METADATA_LENGTH]) {
        out.fill(0);
        out[0] = 1;
        out[1] = u8::from(self.key.is_some());
        out[2..10].copy_from_slice(&self.handle);
        if let Some(key) = &self.key {
            out[10..].copy_from_slice(key);
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != METADATA_LENGTH || bytes[0] != 1 || bytes[1] > 1 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            handle: bytes[2..10].try_into().map_err(|_| Error::Invalid)?,
            key: if bytes[1] == 1 {
                Some(bytes[10..].try_into().map_err(|_| Error::Invalid)?)
            } else {
                None
            },
        })
    }
    fn clear(&mut self, crypto: &mut dyn Crypto) {
        if let Some(key) = &mut self.key {
            crypto.wipe(key);
        }
        self.key = None;
    }
}
pub trait Repository {
    /// Missing metadata is explicit; I/O/corrupt metadata is never treated as first install.
    fn load(&mut self) -> Result<Option<Metadata>, Error>;
    fn replace(&mut self, value: &Metadata) -> Result<(), Error>;
}
pub fn install(repository: &mut dyn Repository, crypto: &mut dyn Crypto) -> Result<(), Error> {
    if let Some(mut value) = repository.load()? {
        value.clear(crypto);
        return Ok(());
    }
    let value = Metadata::new(crypto)?;
    repository.replace(&value)
}
pub struct Selection {
    pub handle: [u8; 8],
    pub challenge: Option<[u8; 8]>,
}
/// Runtime-owned per-session mechanism state, reset on deselection/transport reset.
#[derive(Default)]
pub struct Session {
    challenge: [u8; 8],
    selected: bool,
    authorized: bool,
}
impl Session {
    pub const fn new() -> Self {
        Self {
            challenge: [0; 8],
            selected: false,
            authorized: false,
        }
    }
    pub fn reset(&mut self, crypto: &mut dyn Crypto) {
        crypto.wipe(&mut self.challenge);
        self.selected = false;
        self.authorized = false;
    }
    pub const fn authorized(&self) -> bool {
        self.authorized
    }
    pub fn select(
        &mut self,
        repository: &mut dyn Repository,
        crypto: &mut dyn Crypto,
    ) -> Result<Selection, Error> {
        self.reset(crypto);
        let mut metadata = repository.load()?.ok_or(Error::Storage)?;
        let result = (|| {
            let challenge = if metadata.key.is_some() {
                crypto.random(&mut self.challenge)?;
                Some(self.challenge)
            } else {
                self.authorized = true;
                None
            };
            self.selected = true;
            Ok(Selection {
                handle: metadata.handle,
                challenge,
            })
        })();
        metadata.clear(crypto);
        result
    }
    pub fn set_code(
        &mut self,
        repository: &mut dyn Repository,
        crypto: &mut dyn Crypto,
        key: &[u8; 16],
        challenge: &[u8],
        response: &[u8; 20],
    ) -> Result<(), Error> {
        if !self.authorized {
            return Err(Error::Unauthorized);
        }
        let mut metadata = repository.load()?.ok_or(Error::Storage)?;
        let mut digest = [0; 64];
        let result = (|| {
            crypto.hmac(Algorithm::Sha1, key, challenge, &mut digest)?;
            if !equal(&digest[..20], response) {
                return Err(Error::Invalid);
            }
            metadata.clear(crypto);
            metadata.key = Some(*key);
            self.authorized = false;
            repository.replace(&metadata)
        })();
        crypto.wipe(&mut digest);
        metadata.clear(crypto);
        result
    }
    pub fn clear_code(
        &mut self,
        repository: &mut dyn Repository,
        crypto: &mut dyn Crypto,
    ) -> Result<(), Error> {
        if !self.authorized {
            return Err(Error::Unauthorized);
        }
        let mut metadata = repository.load()?.ok_or(Error::Storage)?;
        metadata.clear(crypto);
        self.authorized = false;
        repository.replace(&metadata)?;
        self.authorized = true;
        Ok(())
    }
    pub fn validate(
        &mut self,
        repository: &mut dyn Repository,
        crypto: &mut dyn Crypto,
        response: &[u8; 20],
        challenge: &[u8],
        output: &mut [u8; 20],
    ) -> Result<(), Error> {
        if !self.selected {
            return Err(Error::Unauthorized);
        }
        self.authorized = false;
        let mut metadata = repository.load()?.ok_or(Error::Storage)?;
        let mut digest = [0; 64];
        let result = (|| {
            let key = metadata.key.as_ref().ok_or(Error::AccessCodeMissing)?;
            crypto.hmac(Algorithm::Sha1, key, &self.challenge, &mut digest)?;
            if !equal(&digest[..20], response) {
                return Err(Error::Unauthorized);
            }
            crypto.hmac(Algorithm::Sha1, key, challenge, &mut digest)?;
            output.copy_from_slice(&digest[..20]);
            self.authorized = true;
            Ok(())
        })();
        crypto.wipe(&mut digest);
        metadata.clear(crypto);
        result
    }
}
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |v, (x, y)| v | (x ^ y)) == 0
}
