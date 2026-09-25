// SPDX-License-Identifier: Apache-2.0
//! Owned hmac-secret inputs and per-enumeration secrets; no Flash state.
use super::{
    Key, Session, Status, credential,
    crypto::{equal, mac},
    pin,
};
use crate::{ports::Platform, runtime::workspace::Workspace};
use canokey_protocol::cbor::Event;

// Sentinel used when a required COSE integer is absent from an incremental map.
// Sentinel for an absent/non-integer COSE label; no valid agreement field uses
// this value.
const COSE_KEY_MISSING: i8 = 127;
const COSE_REQUIRED_MASK: u8 = 0x1f;
const HMAC_COSE_REQUIRED_MASK: u8 = 0x07;

pub struct Parameters {
    agreement: [u8; 64],
    salt: [u8; 80],
    auth: [u8; 32],
    salt_len: usize,
    auth_len: usize,
    protocol: u8,
}
impl Parameters {
    pub const fn new() -> Self {
        Self {
            agreement: [0; 64],
            salt: [0; 80],
            auth: [0; 32],
            salt_len: 0,
            auth_len: 0,
            protocol: 1,
        }
    }
    pub(crate) fn clear(&mut self, memory: &dyn crate::ports::Memory) {
        memory.wipe(&mut self.agreement);
        memory.wipe(&mut self.salt);
        memory.wipe(&mut self.auth);
    }
}
/// The outer credential parser delegates just the extension's integer map here.
pub struct Parser {
    pub params: Parameters,
    previous: [Option<Key>; 2],
    key: Option<Option<i8>>,
    cose: bool,
    seen: u8,
    cose_seen: u8,
    body: Option<(i8, usize)>,
    skip: u8,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            params: Parameters::new(),
            previous: [None; 2],
            key: None,
            cose: false,
            seen: 0,
            cose_seen: 0,
            body: None,
            skip: 0,
        }
    }
    /// Returns true only after the extension map has closed and validated.
    pub fn event(&mut self, event: Event<'_>) -> Result<bool, Status> {
        if super::skip_cbor_event(&mut self.skip, event) {
            return Ok(false);
        }
        if let Some((key, _)) = self.body {
            let out: &mut [u8] = match key {
                -2 => &mut self.params.agreement[..32],
                -3 => &mut self.params.agreement[32..],
                2 => &mut self.params.salt,
                _ => &mut self.params.auth,
            };
            super::consume_cbor_body(event, &mut self.body, out)?;
            return Ok(false);
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                if self.cose {
                    if self.cose_seen != COSE_REQUIRED_MASK {
                        return Err(Status::MissingParameter);
                    }
                    self.cose = false;
                    return Ok(false);
                }
                if self.seen & HMAC_COSE_REQUIRED_MASK != HMAC_COSE_REQUIRED_MASK {
                    return Err(Status::MissingParameter);
                }
                let p = &self.params;
                let iv = if p.protocol == 2 { 16 } else { 0 };
                if p.salt_len != 32 + iv && p.salt_len != 64 + iv {
                    return Err(Status::InvalidParameter);
                }
                if p.auth_len != if p.protocol == 1 { 16 } else { 32 } {
                    return Err(Status::InvalidParameter);
                }
                return Ok(true);
            }
            let previous = &mut self.previous[usize::from(self.cose)];
            let key = Key::ordered(event, previous)?;
            self.key = Some(key);
            return Ok(false);
        };
        let key = key.unwrap_or(COSE_KEY_MISSING);
        if self.cose {
            let bit = super::cose_key_field(key, event)?;
            if bit == 0 {
                self.ignore(event);
            } else {
                if matches!(key, -2 | -3) {
                    self.bytes(key, event, 32, 32)?;
                }
                self.cose_seen |= bit;
            }
        } else {
            match key {
                1 => {
                    if !matches!(event, Event::Map(_)) {
                        return Err(Status::UnexpectedType);
                    }
                    self.seen |= 1;
                    self.cose = true;
                }
                2 => {
                    self.seen |= 2;
                    self.params.salt_len = self.bytes(key, event, 32, 80)?;
                }
                3 => {
                    self.seen |= 4;
                    self.params.auth_len = self.bytes(key, event, 16, 32)?;
                }
                4 => match event {
                    Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                    _ => return Err(Status::InvalidParameter),
                },
                _ => self.ignore(event),
            }
        }
        Ok(false)
    }
    fn bytes(&mut self, key: i8, event: Event<'_>, min: u16, max: u16) -> Result<usize, Status> {
        let Event::Bytes(n) = event else {
            return Err(Status::UnexpectedType);
        };
        if n < min || n > max {
            return Err(Status::InvalidParameter);
        }
        self.body = Some((key, 0));
        Ok(usize::from(n))
    }
    fn ignore(&mut self, event: Event<'_>) {
        if super::is_cbor_container(event) {
            self.skip = 1;
        }
    }
}

pub(super) struct Prepared {
    salts: [u8; 80],
    aes_key: [u8; 32],
    length: usize,
    protocol: u8,
}
impl Prepared {
    pub const fn new() -> Self {
        Self {
            salts: [0; 80],
            aes_key: [0; 32],
            length: 0,
            protocol: 1,
        }
    }
    pub fn clear(&mut self, memory: &dyn crate::ports::Memory) {
        memory.wipe(&mut self.salts);
        memory.wipe(&mut self.aes_key);
        self.length = 0;
    }
    pub fn active(&self) -> bool {
        self.length != 0
    }
    pub fn output(
        &self,
        id: &credential::Id,
        rp: &[u8; 32],
        uv: bool,
        out: &mut [u8; 80],
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let mut random = [0; 32];
        let result = (|| {
            credential::extension_key(if uv { 4 } else { 3 }, id, rp, &mut random, p)?;
            let iv_len = if self.protocol == 2 { 16 } else { 0 };
            let mut iv = [0; 16];
            if iv_len != 0 {
                p.crypto.random(&mut iv).map_err(|_| Status::Other)?;
                out[..16].copy_from_slice(&iv);
            }
            for (salt, output) in self.salts[..self.length]
                .chunks_exact(32)
                .zip(out[iv_len..iv_len + self.length].chunks_exact_mut(32))
            {
                mac(&random, salt, output.try_into().unwrap(), p)?;
            }
            p.crypto
                .aes256_cbc(
                    true,
                    &self.aes_key,
                    &iv,
                    &mut out[iv_len..iv_len + self.length],
                )
                .map_err(|_| Status::Other)?;
            Ok(iv_len + self.length)
        })();
        p.memory.wipe(&mut random);
        if result.is_err() {
            p.memory.wipe(out);
        }
        result
    }
}
impl Session {
    pub(super) fn prepare_hmac(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Status> {
        let mut shared = [0; 64];
        let mut expected = [0; 32];
        let result = (|| {
            self.decapsulate(params.protocol, &params.agreement, &mut shared, w, p)?;
            mac(
                &shared[..32],
                &params.salt[..params.salt_len],
                &mut expected,
                p,
            )?;
            if !equal(
                &expected[..params.auth_len],
                &params.auth[..params.auth_len],
            ) {
                return Err(Status::PinAuthInvalid);
            }
            let prepared = &mut self.assertion.hmac;
            prepared.aes_key.copy_from_slice(&shared[32..]);
            prepared.salts[..params.salt_len].copy_from_slice(&params.salt[..params.salt_len]);
            pin::decrypt(
                params.protocol,
                &prepared.aes_key,
                &mut prepared.salts[..params.salt_len],
                p,
            )?;
            prepared.protocol = params.protocol;
            prepared.length = params.salt_len - if params.protocol == 2 { 16 } else { 0 };
            Ok(())
        })();
        p.memory.wipe(&mut shared);
        p.memory.wipe(&mut expected);
        if result.is_err() {
            self.assertion.hmac.clear(p.memory);
        }
        result
    }
}
