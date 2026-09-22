// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

pub const PASSWORD_LIMIT: usize = 32;
pub const NAME_LIMIT: usize = 64;
pub const KEY_LENGTH: usize = 20;
pub const CHALLENGE_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Slot,
    Length,
    Kind,
    Record,
    Crypto,
    Output,
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

/// Semantic slot data, borrowed for one operation; never a native struct image.
#[derive(Clone, Copy)]
pub enum Slot<'a> {
    Off,
    Static {
        password: &'a [u8],
        enter: u8,
    },
    Hmac(&'a [u8; KEY_LENGTH]),
    Oath {
        offset: u32,
        name: &'a [u8],
        enter: u8,
    },
    Unknown(u32),
}

impl Slot<'_> {
    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Static { password, .. } if password.len() > PASSWORD_LIMIT => Err(Error::Length),
            Self::Oath { name, .. } if name.len() > NAME_LIMIT => Err(Error::Length),
            Self::Unknown(_) => Err(Error::Kind),
            _ => Ok(()),
        }
    }
}

pub trait Crypto {
    /// Writes four big-endian bytes; returns the number of decimal digits.
    fn oath(&mut self, offset: u32, code: &mut [u8; 4]) -> i32;
    fn hmac(&mut self, key: &[u8; KEY_LENGTH], challenge: &[u8], output: &mut [u8; KEY_LENGTH]);
}

pub fn challenge_response(
    slot: Slot<'_>,
    challenge: &[u8],
    output: &mut [u8; KEY_LENGTH],
    crypto: &mut dyn Crypto,
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

pub enum Output<'a> {
    None,
    Static {
        password: &'a [u8],
        enter: u8,
    },
    Decimal {
        value: u32,
        digits: usize,
        enter: u8,
    },
}

impl Output<'_> {
    pub fn capacity(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Static { password, enter } => password.len() + usize::from(*enter != 0),
            Self::Decimal { digits, .. } => digits + 1, // Includes the existing NUL write.
        }
    }
    pub fn write(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.capacity() {
            return Err(Error::Output);
        }
        let (mut len, enter) = match self {
            Self::None => return Ok(0),
            Self::Static { password, enter } => {
                output[..password.len()].copy_from_slice(password);
                (password.len(), enter)
            }
            Self::Decimal {
                mut value,
                digits,
                enter,
            } => {
                for byte in output[..digits].iter_mut().rev() {
                    *byte = (value % 10) as u8 + b'0';
                    value /= 10;
                }
                output[digits] = 0;
                (digits, enter)
            }
        };
        if enter != 0 {
            output[len] = b'\r';
            len += 1;
        }
        Ok(len)
    }
}

pub fn prepare_output<'a>(slot: Slot<'a>, crypto: &mut dyn Crypto) -> Result<Output<'a>, Error> {
    Ok(match slot {
        Slot::Off | Slot::Hmac(_) => Output::None,
        Slot::Static { password, enter } => Output::Static { password, enter },
        Slot::Oath { offset, enter, .. } => {
            let mut code = [0; 4];
            let digits = crypto.oath(offset, &mut code);
            if !(0..=10).contains(&digits) {
                return Err(Error::Crypto);
            }
            Output::Decimal {
                value: u32::from_be_bytes(code),
                digits: digits as usize,
                enter,
            }
        }
        Slot::Unknown(_) => return Err(Error::Record),
    })
}
