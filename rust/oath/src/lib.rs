// SPDX-License-Identifier: Apache-2.0
//! OATH domain and services. No APDU, status words, FFI or transport dependency.
#![no_std]
#![forbid(unsafe_code)]
pub mod auth;
pub mod codec;
pub mod credential;
pub mod service;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Missing,
    Duplicate,
    Storage,
    NoSpace,
    Crypto,
    CounterExhausted,
    IncreasingChallenge,
    PresenceRequired,
    Unauthorized,
    AccessCodeMissing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}
impl Algorithm {
    pub const fn digest_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha512),
            _ => Err(Error::Invalid),
        }
    }
}
/// Existing platform primitives; implementations must wipe temporary key state.
pub trait Crypto {
    fn hmac(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        message: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), Error>;
    fn random(&mut self, out: &mut [u8]) -> Result<(), Error>;
    fn wipe(&mut self, bytes: &mut [u8]);
}
