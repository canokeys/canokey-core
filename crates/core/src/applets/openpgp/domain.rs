// SPDX-License-Identifier: Apache-2.0
//! OpenPGP key roles and algorithm attributes; no transport or platform calls.
use super::wire::reference;
use crate::ports::alg;
const EC_P256_BYTES: usize = 32;
const EC_P384_BYTES: usize = 48;
const EC_P521_BYTES: usize = 66;
const RSA2048_COMPONENT_BYTES: usize = 128;
const RSA3072_COMPONENT_BYTES: usize = 192;
const RSA4096_COMPONENT_BYTES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(pub u8);
impl Algorithm {
    pub fn rsa(self) -> bool {
        (alg::RSA2048..=alg::RSA4096).contains(&self.0)
    }
    /// Active bytes in one private component: EC scalar/seed or RSA prime.
    pub fn private_component_bytes(self) -> usize {
        match self.0 {
            alg::P256 | alg::SECP256K1 | alg::ED25519 | alg::X25519 => EC_P256_BYTES,
            alg::P384 => EC_P384_BYTES,
            alg::RSA2048 => RSA2048_COMPONENT_BYTES,
            alg::RSA3072 => RSA3072_COMPONENT_BYTES,
            alg::RSA4096 => RSA4096_COMPONENT_BYTES,
            alg::P521 => EC_P521_BYTES,
            _ => 0,
        }
    }
    /// Raw public value bytes: RSA modulus, EC X||Y, or Ed/X25519 encoding.
    /// Excludes RSA exponent, SEC1 point prefix and TLV wrappers.
    pub fn public_value_bytes(self) -> usize {
        if self.0 == alg::ED25519 || self.0 == alg::X25519 {
            EC_P256_BYTES
        } else {
            2 * self.private_component_bytes()
        }
    }
    // OpenPGP algorithm attributes: EC uses an algorithm byte followed by an
    // OID; RSA uses algorithm, modulus bits (u16 BE), exponent bits (u16 BE),
    // and import format. These bytes are independent of native ports::alg IDs.
    pub fn attrs(self, role: usize, out: &mut [u8; 12]) -> usize {
        let attr: &[u8] = match self.0 {
            alg::P256 => &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            alg::SECP256K1 => &[0x13, 0x2b, 0x81, 0x04, 0x00, 0x0a],
            alg::P384 => &[0x13, 0x2b, 0x81, 0x04, 0x00, 0x22],
            alg::P521 => &[0x13, 0x2b, 0x81, 0x04, 0x00, 0x23],
            alg::ED25519 => &[0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01],
            alg::X25519 => &[
                0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
            ],
            alg::RSA2048 => &[0x01, 0x08, 0x00, 0x00, 0x20, 0x02],
            alg::RSA3072 => &[0x01, 0x0c, 0x00, 0x00, 0x20, 0x02],
            alg::RSA4096 => &[0x01, 0x10, 0x00, 0x00, 0x20, 0x02],
            _ => return 0,
        };
        out[..attr.len()].copy_from_slice(attr);
        if role == key_role::DECIPHER
            && matches!(self.0, alg::P256 | alg::SECP256K1 | alg::P384 | alg::P521)
        {
            out[0] = 0x12;
        }
        attr.len()
    }
    pub fn allowed(self, role: usize) -> bool {
        let decipher = role == key_role::DECIPHER;
        if decipher {
            self.0 != alg::ED25519
        } else {
            self.0 != alg::X25519
        }
    }
    pub fn parse(bytes: &[u8], role: usize) -> Option<Self> {
        let mut attr = [0; 12];
        (alg::P256..=alg::P521).map(Self).find(|a| {
            a.allowed(role) && {
                let n = a.attrs(role, &mut attr);
                bytes == &attr[..n]
            }
        })
    }
}
pub fn role(reference: u8) -> Option<usize> {
    match reference {
        reference::SIGNATURE => Some(key_role::SIGNATURE),
        reference::DECIPHER => Some(key_role::DECIPHER),
        reference::AUTHENTICATION => Some(key_role::AUTHENTICATION),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Storage,
    Crypto,
    Data,
    Length,
    Blocked,
    Unauthorized,
    Missing,
    Presence,
}

pub(super) mod key_role {
    pub const SIGNATURE: usize = 0;
    pub const DECIPHER: usize = 1;
    pub const AUTHENTICATION: usize = 2;
    pub const COUNT: usize = 3;
}
pub(super) mod grant {
    pub const SIGNATURE: u8 = 1;
    pub const OTHER: u8 = 2;
    pub const ADMIN: u8 = 4;
    pub const PW1: u8 = SIGNATURE | OTHER;
}
pub(super) mod touch_policy {
    pub const DISABLED: u8 = 0;
    pub const FIXED: u8 = 2;
}
