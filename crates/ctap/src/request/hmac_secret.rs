// SPDX-License-Identifier: Apache-2.0
//! Owned hmac-secret input parsing; crypto and prepared secrets stay with owners.
use super::{
    Error, agreement,
    stream::{self, Key},
};
use crate::client_pin::Protocol;
use canokey_protocol::cbor::Event;
mod wire {
    use super::Protocol;
    pub const V1: u8 = Protocol::One as u8;
    pub const V2: u8 = Protocol::Two as u8;
    pub const AES_BLOCK_BYTES: usize = crate::client_pin::cipher::BLOCK_BYTES;
    pub const AUTH_V1_BYTES: usize = Protocol::One.auth_bytes();
    pub const AUTH_V2_BYTES: usize = Protocol::Two.auth_bytes();
}
// One/two SHA-256 salts, optionally preceded by the v2 AES IV.
const SALT_BYTES: usize = 32;
const DOUBLE_SALT_BYTES: usize = 2 * SALT_BYTES;
const MAX_ENCRYPTED_SALT_BYTES: usize = wire::AES_BLOCK_BYTES + DOUBLE_SALT_BYTES;

// Sentinel for a non-integer/unsupported-width label. It is outside the
// recognized hmac-secret extension labels 1..=4 and follows the skip path.
const COSE_KEY_MISSING: i8 = 127;
const HMAC_COSE_REQUIRED_MASK: u8 = 0x07;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parameters {
    pub salt_len: usize,
    pub auth_len: usize,
    pub protocol: u8,
    pub agreement: [u8; 64],
    pub salt: [u8; MAX_ENCRYPTED_SALT_BYTES],
    pub auth: [u8; 32],
}
impl Parameters {
    pub const fn new() -> Self {
        Self {
            agreement: [0; 64],
            salt: [0; MAX_ENCRYPTED_SALT_BYTES],
            auth: [0; 32],
            salt_len: 0,
            auth_len: 0,
            protocol: wire::V1,
        }
    }
    pub fn clear(&mut self, memory: &(impl canokey_ports::Memory + ?Sized)) {
        memory.wipe(&mut self.agreement);
        memory.wipe(&mut self.salt);
        memory.wipe(&mut self.auth);
    }
}
/// The outer credential parser delegates just the extension's integer map here.
pub struct Parser<E: Error> {
    pub params: Parameters,
    previous: Option<Key<E>>,
    agreement: agreement::Parser<E>,
    key: Option<Option<i8>>,
    cose: bool,
    seen: u8,
    body: Option<(i8, usize)>,
    skip: u8,
}
impl<E: Error> Parser<E> {
    pub const fn new() -> Self {
        Self {
            params: Parameters::new(),
            previous: None,
            agreement: agreement::Parser::new(),
            key: None,
            cose: false,
            seen: 0,
            body: None,
            skip: 0,
        }
    }
    /// Returns true only after the extension map has closed and validated.
    pub fn event(&mut self, event: &Event<'_>) -> Result<bool, E> {
        if self.cose {
            if self
                .agreement
                .event(event, &mut self.params.agreement, E::INVALID_PARAMETER)?
            {
                self.cose = false;
            }
            return Ok(false);
        }
        if stream::skip_cbor_event(&mut self.skip, event)? {
            return Ok(false);
        }
        if let Some((key, _)) = self.body {
            let out: &mut [u8] = match key {
                2 => &mut self.params.salt,
                _ => &mut self.params.auth,
            };
            stream::consume_cbor_body(event, &mut self.body, out)?;
            return Ok(false);
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                if self.seen & HMAC_COSE_REQUIRED_MASK != HMAC_COSE_REQUIRED_MASK {
                    return Err(E::MISSING_PARAMETER);
                }
                let p = &self.params;
                let iv = if p.protocol == wire::V2 {
                    wire::AES_BLOCK_BYTES
                } else {
                    0
                };
                if p.salt_len != SALT_BYTES + iv && p.salt_len != DOUBLE_SALT_BYTES + iv {
                    return Err(E::INVALID_LENGTH);
                }
                if p.auth_len
                    != if p.protocol == wire::V1 {
                        wire::AUTH_V1_BYTES
                    } else {
                        wire::AUTH_V2_BYTES
                    }
                {
                    return Err(E::INVALID_PARAMETER);
                }
                return Ok(true);
            }
            let key = Key::ordered(event, &mut self.previous)?;
            self.key = Some(key);
            return Ok(false);
        };
        let key = key.unwrap_or(COSE_KEY_MISSING);
        match key {
            1 => {
                if !matches!(event, Event::Map(_)) {
                    return Err(E::UNEXPECTED_TYPE);
                }
                self.seen |= 1;
                self.cose = true;
            }
            2 => {
                self.seen |= 2;
                self.params.salt_len = self.bytes(
                    key,
                    event,
                    SALT_BYTES as u16,
                    MAX_ENCRYPTED_SALT_BYTES as u16,
                )?;
            }
            3 => {
                self.seen |= 4;
                self.params.auth_len = self.bytes(
                    key,
                    event,
                    wire::AUTH_V1_BYTES as u16,
                    wire::AUTH_V2_BYTES as u16,
                )?;
            }
            4 => match *event {
                Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                _ => return Err(E::INVALID_PARAMETER),
            },
            _ => self.ignore(event),
        }
        Ok(false)
    }
    fn bytes(&mut self, key: i8, event: &Event<'_>, min: u16, max: u16) -> Result<usize, E> {
        let Event::Bytes(n) = *event else {
            return Err(E::UNEXPECTED_TYPE);
        };
        if n < min || n > max {
            return Err(if key == 2 {
                E::INVALID_LENGTH
            } else {
                E::INVALID_PARAMETER
            });
        }
        self.body = Some((key, 0));
        Ok(usize::from(n))
    }
    fn ignore(&mut self, event: &Event<'_>) {
        if stream::is_cbor_container(event) {
            self.skip = 1;
        }
    }
}
