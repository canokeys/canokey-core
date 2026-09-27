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
impl Kind {
    pub const MASK: u8 = 0xf0;
    pub const ALGORITHM_MASK: u8 = 0x0f;
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value & Self::MASK {
            value if value == Self::Hotp as u8 => Ok(Self::Hotp),
            value if value == Self::Totp as u8 => Ok(Self::Totp),
            _ => Err(Error::Invalid),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Properties(u8);
impl Properties {
    const INCREASING: u8 = 1;
    const TOUCH: u8 = 2;
    pub fn new(value: u8) -> Result<Self, Error> {
        if value & !(Self::INCREASING | Self::TOUCH) == 0 {
            Ok(Self(value))
        } else {
            Err(Error::Invalid)
        }
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn increasing(self) -> bool {
        self.0 & Self::INCREASING != 0
    }
    pub const fn touch(self) -> bool {
        self.0 & Self::TOUCH != 0
    }
}
/// Not Debug/Copy: keys are explicitly borrowed and cleared, never logged.
pub struct Credential {
    // Validated compact record; the unused tail is always zero. Keeping the
    // wire storage avoids a second key-bearing decode/encode representation.
    pub(super) bytes: [u8; super::codec::LENGTH],
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
            bytes: [0; super::codec::LENGTH],
        };
        value.bytes[..6].copy_from_slice(&[
            1,
            name.len() as u8,
            key.len() as u8,
            kind as u8 | algorithm as u8,
            digits,
            properties.bits(),
        ]);
        let key_at = 6 + name.len();
        let counter_at = key_at + key.len();
        value.bytes[6..key_at].copy_from_slice(name);
        value.bytes[key_at..counter_at].copy_from_slice(key);
        value.bytes[counter_at..counter_at + 8].copy_from_slice(&moving_factor);
        Ok(value)
    }
    pub(super) fn encoded_length(&self) -> usize {
        14 + usize::from(self.bytes[1]) + usize::from(self.bytes[2])
    }
    pub fn name(&self) -> &[u8] {
        &self.bytes[6..6 + usize::from(self.bytes[1])]
    }
    pub fn key(&self) -> &[u8] {
        let at = 6 + usize::from(self.bytes[1]);
        &self.bytes[at..at + usize::from(self.bytes[2])]
    }
    pub const fn algorithm(&self) -> Algorithm {
        match self.bytes[3] & Kind::ALGORITHM_MASK {
            1 => Algorithm::Sha1,
            2 => Algorithm::Sha256,
            _ => Algorithm::Sha512,
        }
    }
    pub const fn kind(&self) -> Kind {
        if self.bytes[3] & Kind::MASK == Kind::Hotp as u8 {
            Kind::Hotp
        } else {
            Kind::Totp
        }
    }
    pub const fn digits(&self) -> u8 {
        self.bytes[4]
    }
    pub const fn properties(&self) -> Properties {
        Properties(self.bytes[5])
    }
    pub fn moving_factor(&self) -> [u8; 8] {
        let end = self.encoded_length();
        self.bytes[end - 8..end].try_into().unwrap()
    }

    pub fn rename(
        &mut self,
        name: &[u8],
        crypto: &mut (impl Crypto + ?Sized),
    ) -> Result<(), Error> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::Invalid);
        }
        let end = self.encoded_length();
        let old_key_at = 6 + usize::from(self.bytes[1]);
        let new_key_at = 6 + name.len();
        self.bytes.copy_within(old_key_at..end, new_key_at);
        self.bytes[6..new_key_at].copy_from_slice(name);
        self.bytes[1] = name.len() as u8;
        let end = self.encoded_length();
        // The old key/counter can survive a shortening in the unused tail.
        crypto.wipe(&mut self.bytes[end..]);
        Ok(())
    }
    pub fn clear(&mut self, crypto: &mut (impl Crypto + ?Sized)) {
        // Wipe through the unused tail as rename can shift the secret.
        let at = 6 + usize::from(self.bytes[1]);
        crypto.wipe(&mut self.bytes[at..]);
        self.bytes[2] = 0;
    }
}
