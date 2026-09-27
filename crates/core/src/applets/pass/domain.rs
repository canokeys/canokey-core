// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
pub const PASSWORD_LIMIT: usize = 32;
pub const KEY_LENGTH: usize = 20;
pub const CHALLENGE_LIMIT: usize = 64;
/// Kind tags shared by ADMIN configuration and PASS persistence.
pub mod kind {
    pub const OFF: u8 = 0;
    pub const OATH: u8 = 1;
    pub const STATIC: u8 = 2;
    pub const HMAC: u8 = 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Slot,
    Length,
    Kind,
    Record,
    Output,
    Persistence,
}
#[derive(Clone, Copy)]
pub struct SlotIndex(usize);
impl SlotIndex {
    pub fn new(index: u8) -> Result<Self, Error> {
        if index < 2 {
            Ok(Self(usize::from(index)))
        } else {
            Err(Error::Slot)
        }
    }
    pub fn get(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy)]
pub enum Slot<'a> {
    Oath { id: u32, name: &'a [u8], enter: u8 },
    Off,
    Static { password: &'a [u8], enter: u8 },
    Hmac(&'a [u8; KEY_LENGTH]),
}
impl Slot<'_> {
    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Oath { id, name, enter }
                if id == 0 || name.is_empty() || name.len() > 64 || enter > 1 =>
            {
                Err(Error::Length)
            }
            Self::Static { password, enter } if password.len() > PASSWORD_LIMIT || enter > 1 => {
                Err(Error::Length)
            }
            _ => Ok(()),
        }
    }
}
pub trait Crypto {
    fn hmac(&mut self, key: &[u8; KEY_LENGTH], challenge: &[u8], output: &mut [u8; KEY_LENGTH]);
}
pub fn challenge_response(
    slot: Slot<'_>,
    challenge: &[u8],
    output: &mut [u8; KEY_LENGTH],
    crypto: &mut (impl Crypto + ?Sized),
) -> Result<(), Error> {
    if challenge.len() > CHALLENGE_LIMIT {
        return Err(Error::Length);
    }
    let Slot::Hmac(key) = slot else {
        return Err(Error::Kind);
    };
    crypto.hmac(key, challenge, output);
    Ok(())
}
pub fn write_output(slot: Slot<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let Slot::Static { password, enter } = slot else {
        return Ok(0);
    };
    let len = password.len() + usize::from(enter != 0);
    if output.len() < len {
        return Err(Error::Output);
    }
    output[..password.len()].copy_from_slice(password);
    if enter != 0 {
        output[password.len()] = b'\r';
    }
    Ok(len)
}
