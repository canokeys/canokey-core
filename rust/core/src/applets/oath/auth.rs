// SPDX-License-Identifier: Apache-2.0
//! Existing OATH access-code challenge protocol, independent of ADMIN PINs.
use super::{Algorithm, Crypto, Error};
use crate::mechanisms::equal;
pub const HANDLE_BYTES: usize = 8;
pub const CHALLENGE_BYTES: usize = 8;
pub const ACCESS_KEY_BYTES: usize = 16;
const FORMAT_VERSION: u8 = 1;
const VERSION: usize = 0;
const KEY_PRESENT: usize = 1;
const HANDLE: usize = 2;
const KEY: usize = HANDLE + HANDLE_BYTES;
pub const METADATA_LENGTH: usize = KEY + ACCESS_KEY_BYTES;
// The handle is a public, persistent applet identity returned on SELECT.
// It is not an authentication token. The optional key is the secret access code.
pub struct Metadata {
    handle: [u8; HANDLE_BYTES],
    key: Option<[u8; ACCESS_KEY_BYTES]>,
}
impl Metadata {
    pub fn new(crypto: &mut (impl Crypto + ?Sized)) -> Result<Self, Error> {
        let mut handle = [0; HANDLE_BYTES];
        crypto.random(&mut handle)?;
        Ok(Self { handle, key: None })
    }
    pub fn encode(&self, out: &mut [u8; METADATA_LENGTH]) -> usize {
        out.fill(0);
        out[VERSION] = FORMAT_VERSION;
        out[KEY_PRESENT] = u8::from(self.key.is_some());
        out[HANDLE..KEY].copy_from_slice(&self.handle);
        if let Some(key) = &self.key {
            out[KEY..].copy_from_slice(key);
            METADATA_LENGTH
        } else {
            KEY
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < KEY
            || bytes[VERSION] != FORMAT_VERSION
            || bytes[KEY_PRESENT] > 1
            || bytes.len()
                != if bytes[KEY_PRESENT] == 1 {
                    METADATA_LENGTH
                } else {
                    KEY
                }
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            handle: bytes[HANDLE..KEY].try_into().map_err(|_| Error::Invalid)?,
            key: if bytes[KEY_PRESENT] == 1 {
                Some(bytes[KEY..].try_into().map_err(|_| Error::Invalid)?)
            } else {
                None
            },
        })
    }
    fn clear(&mut self, crypto: &mut (impl Crypto + ?Sized)) {
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
pub fn install(
    repository: &mut (impl Repository + ?Sized),
    crypto: &mut (impl Crypto + ?Sized),
) -> Result<(), Error> {
    if let Some(mut value) = repository.load()? {
        value.clear(crypto);
        return Ok(());
    }
    let value = Metadata::new(crypto)?;
    repository.replace(&value)
}
pub struct Selection {
    pub handle: [u8; HANDLE_BYTES],
    pub challenge: Option<[u8; CHALLENGE_BYTES]>,
}
/// Runtime-owned per-session mechanism state, reset on deselection/transport reset.
#[derive(Default)]
pub struct Session {
    challenge: [u8; CHALLENGE_BYTES],
    selected: bool,
    authorized: bool,
}
impl Session {
    pub const fn new() -> Self {
        Self {
            challenge: [0; CHALLENGE_BYTES],
            selected: false,
            authorized: false,
        }
    }
    pub fn reset(&mut self, crypto: &mut (impl Crypto + ?Sized)) {
        crypto.wipe(&mut self.challenge);
        self.selected = false;
        self.authorized = false;
    }
    pub const fn authorized(&self) -> bool {
        self.authorized
    }
    pub fn select(
        &mut self,
        repository: &mut (impl Repository + ?Sized),
        crypto: &mut (impl Crypto + ?Sized),
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
    // The supplied MAC proves knowledge of the NEW key before it is stored;
    // authorization to replace the old key is checked separately below.
    pub fn set_code(
        &mut self,
        repository: &mut (impl Repository + ?Sized),
        crypto: &mut (impl Crypto + ?Sized),
        key: &[u8; ACCESS_KEY_BYTES],
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
        repository: &mut (impl Repository + ?Sized),
        crypto: &mut (impl Crypto + ?Sized),
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
    // Verify the host MAC over our SELECT challenge, then return a MAC over
    // the host challenge. This authenticates both sides using the access key.
    pub fn validate(
        &mut self,
        repository: &mut (impl Repository + ?Sized),
        crypto: &mut (impl Crypto + ?Sized),
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
            // Consume the SELECT challenge after one successful validation so
            // the same response cannot be replayed in this selection.
            crypto.random(&mut self.challenge)?;
            self.authorized = true;
            Ok(())
        })();
        crypto.wipe(&mut digest);
        metadata.clear(crypto);
        result
    }
}
