// SPDX-License-Identifier: Apache-2.0
use super::{Algorithm, Crypto, Error, codec};
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
    // Fixed storage encoding; unused name/key bytes are always zero.
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
            codec::FORMAT_VERSION,
            name.len() as u8,
            key.len() as u8,
            kind as u8 | algorithm as u8,
            digits,
            properties.bits(),
        ]);
        value.bytes[6..6 + name.len()].copy_from_slice(name);
        value.bytes[codec::KEY_OFFSET..codec::KEY_OFFSET + key.len()].copy_from_slice(key);
        value.bytes[codec::COUNTER_OFFSET..].copy_from_slice(&moving_factor);
        Ok(value)
    }
    pub fn name(&self) -> &[u8] {
        &self.bytes[6..6 + usize::from(self.bytes[1])]
    }
    pub fn key(&self) -> &[u8] {
        let at = codec::KEY_OFFSET;
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
        self.bytes[codec::COUNTER_OFFSET..].try_into().unwrap()
    }

    pub fn rename(
        &mut self,
        name: &[u8],
        crypto: &mut (impl Crypto + ?Sized),
    ) -> Result<(), Error> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::Invalid);
        }
        crypto.wipe(&mut self.bytes[6..codec::KEY_OFFSET]);
        self.bytes[6..6 + name.len()].copy_from_slice(name);
        self.bytes[1] = name.len() as u8;
        Ok(())
    }
    pub fn clear(&mut self, crypto: &mut (impl Crypto + ?Sized)) {
        crypto.wipe(&mut self.bytes[codec::KEY_OFFSET..]);
        self.bytes[2] = 0;
    }
}
