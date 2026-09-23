// SPDX-License-Identifier: Apache-2.0
use super::{Algorithm, Crypto, Error};
pub const NAME_LIMIT: usize = 64;
pub const KEY_LIMIT: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hotp = 0x10,
    Totp = 0x20,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Properties(u8);
impl Properties {
    pub fn new(value: u8) -> Result<Self, Error> {
        if value & !3 == 0 {
            Ok(Self(value))
        } else {
            Err(Error::Invalid)
        }
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn increasing(self) -> bool {
        self.0 & 1 != 0
    }
    pub const fn touch(self) -> bool {
        self.0 & 2 != 0
    }
}
/// Not Debug/Copy: keys are explicitly borrowed and cleared, never logged.
pub struct Credential {
    pub(crate) name: [u8; NAME_LIMIT],
    pub(crate) name_len: u8,
    pub(crate) key: [u8; KEY_LIMIT],
    pub(crate) key_len: u8,
    pub(crate) algorithm: Algorithm,
    pub(crate) kind: Kind,
    pub(crate) digits: u8,
    pub(crate) properties: Properties,
    pub(crate) moving_factor: [u8; 8],
}
impl Credential {
    pub fn new(
        name: &[u8],
        key: &[u8],
        kind: Kind,
        algorithm: Algorithm,
        digits: u8,
        properties: Properties,
        moving_factor: [u8; 8],
    ) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > NAME_LIMIT
            || key.is_empty()
            || key.len() > KEY_LIMIT
            || !(4..=8).contains(&digits)
        {
            return Err(Error::Invalid);
        }
        let mut value = Self {
            name: [0; 64],
            name_len: name.len() as u8,
            key: [0; 64],
            key_len: key.len() as u8,
            kind,
            algorithm,
            digits,
            properties,
            moving_factor,
        };
        value.name[..name.len()].copy_from_slice(name);
        value.key[..key.len()].copy_from_slice(key);
        Ok(value)
    }
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
    pub fn key(&self) -> &[u8] {
        &self.key[..usize::from(self.key_len)]
    }
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    pub const fn digits(&self) -> u8 {
        self.digits
    }
    pub const fn properties(&self) -> Properties {
        self.properties
    }
    pub const fn moving_factor(&self) -> [u8; 8] {
        self.moving_factor
    }
    pub fn rename(&mut self, name: &[u8]) -> Result<(), Error> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::Invalid);
        }
        self.name.fill(0);
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len() as u8;
        Ok(())
    }
    pub fn clear(&mut self, crypto: &mut dyn Crypto) {
        crypto.wipe(&mut self.key);
        self.key_len = 0;
    }
}
