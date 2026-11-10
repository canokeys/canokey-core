// SPDX-License-Identifier: Apache-2.0
//! Owned hmac-secret input parsing; crypto and prepared secrets stay with owners.
use super::{
    Error, agreement,
    stream::{self, Key},
};
use crate::client_pin::Protocol;
use canokey_protocol::cbor::Event;
pub mod borrowed;

// CTAP 2.1 hmac-secret assertion input map labels.
pub const KEY_AGREEMENT: i8 = 0x01;
pub const SALT_ENC: i8 = 0x02;
pub const SALT_AUTH: i8 = 0x03;
pub const PIN_PROTOCOL: i8 = 0x04;
mod wire {
    use super::Protocol;
    pub const AUTH_V1_BYTES: usize = Protocol::One.auth_bytes();
    pub const AUTH_V2_BYTES: usize = Protocol::Two.auth_bytes();
}
// One/two SHA-256 salts, optionally preceded by the v2 AES IV.
const MAX_ENCRYPTED_SALT_BYTES: usize = crate::extensions::hmac_secret::MAX_OUTPUT_BYTES;

// Sentinel for a non-integer/unsupported-width label. It is outside the
// recognized hmac-secret extension labels 1..=4 and follows the skip path.
const COSE_KEY_MISSING: i8 = 127;
const HMAC_COSE_REQUIRED_MASK: u8 = 0x07;

/// Bounded body admission precedes missing-field checks, matching streaming
/// input. The final protocol-specific check waits until the map closes.
#[inline(always)]
pub(crate) fn admit_body<E: Error>(field: i8, length: usize) -> Result<(), E> {
    let valid = if field == SALT_ENC {
        length >= crate::extensions::hmac_secret::SALT_BYTES && length <= MAX_ENCRYPTED_SALT_BYTES
    } else {
        length >= wire::AUTH_V1_BYTES && length <= wire::AUTH_V2_BYTES
    };
    if valid {
        Ok(())
    } else if field == SALT_ENC {
        Err(E::INVALID_LENGTH)
    } else {
        Err(E::INVALID_PARAMETER)
    }
}
#[inline(always)]
pub(crate) fn admit_fields<E: Error>(
    seen: u8,
    protocol: Protocol,
    salt: usize,
    auth: usize,
) -> Result<(), E> {
    if seen & HMAC_COSE_REQUIRED_MASK != HMAC_COSE_REQUIRED_MASK {
        return Err(E::MISSING_PARAMETER);
    }
    if crate::extensions::hmac_secret::salt_length(protocol, salt).is_none() {
        return Err(E::INVALID_LENGTH);
    }
    if auth != protocol.auth_bytes() {
        return Err(E::INVALID_PARAMETER);
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parameters {
    pub salt_len: usize,
    pub auth_len: usize,
    pub protocol: Protocol,
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
            protocol: Protocol::One,
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
                let p = &self.params;
                admit_fields::<E>(self.seen, p.protocol, p.salt_len, p.auth_len)?;
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
                self.params.salt_len = self.bytes(key, event)?;
            }
            3 => {
                self.seen |= 4;
                self.params.auth_len = self.bytes(key, event)?;
            }
            4 => match *event {
                Event::Unsigned(n) => {
                    self.params.protocol = Protocol::decode(n).ok_or(E::INVALID_PARAMETER)?;
                }
                _ => return Err(E::INVALID_PARAMETER),
            },
            _ => self.ignore(event),
        }
        Ok(false)
    }
    #[inline(always)]
    fn bytes(&mut self, key: i8, event: &Event<'_>) -> Result<usize, E> {
        let Event::Bytes(n) = *event else {
            return Err(E::UNEXPECTED_TYPE);
        };
        admit_body::<E>(key, usize::from(n))?;
        self.body = Some((key, 0));
        Ok(usize::from(n))
    }
    fn ignore(&mut self, event: &Event<'_>) {
        if stream::is_cbor_container(event) {
            self.skip = 1;
        }
    }
}
