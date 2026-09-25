// SPDX-License-Identifier: Apache-2.0
//! Incremental clientPIN schema. Only owned fields survive request release.
use super::{Command, Key, Status};
use canokey_protocol::cbor::Event;

// Sentinel used when a required COSE integer is absent from an incremental map.
// Outside the signed i8 COSE key labels; forces an absent/non-integer label
// through the unknown-member path without colliding with a valid field.
const COSE_KEY_MISSING: i8 = 127;

pub struct Parameters {
    pub protocol: u8,
    pub subcommand: u8,
    pub agreement: [u8; 64],
    pub auth: [u8; 32],
    pub new_pin: [u8; 80],
    pub pin_hash: [u8; 32],
    pub permissions: u8,
    pub rp: [u8; 254],
    pub rp_len: usize,
}
impl Parameters {
    const fn new() -> Self {
        Self {
            protocol: 0,
            subcommand: 0,
            agreement: [0; 64],
            auth: [0; 32],
            new_pin: [0; 80],
            pin_hash: [0; 32],
            permissions: 0,
            rp: [0; 254],
            rp_len: 0,
        }
    }
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::new(),
            fields: Fields::new(),
        }
    }
    // Share this parser across HID and APDU callers on size-constrained targets.
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let fields = &mut self.fields;
        self.decoder
            .consume(bytes, &mut |event, _| fields.event(event));
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.fields.params.agreement);
        memory.wipe(&mut self.fields.params.auth);
        memory.wipe(&mut self.fields.params.new_pin);
        memory.wipe(&mut self.fields.params.pin_hash);
        memory.wipe(&mut self.fields.params.rp);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let f = &mut self.fields;
        if f.seen & (1 << 2) == 0 {
            return Err(Status::MissingParameter);
        }
        let required = match f.params.subcommand {
            1 => return Ok(Command::GetPinRetries),
            2 => 1 << 1,
            3 => (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5),
            4 => (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6),
            5 => (1 << 1) | (1 << 3) | (1 << 6),
            9 => (1 << 1) | (1 << 3) | (1 << 6) | (1 << 9),
            _ => return Err(Status::InvalidSubcommand),
        };
        if f.seen & required != required {
            return Err(Status::MissingParameter);
        }
        if f.params.subcommand == 5 && f.seen & ((1 << 9) | (1 << 10)) != 0 {
            return Err(Status::InvalidParameter);
        }
        if f.params.subcommand == 9 && f.params.permissions & 3 != 0 && f.params.rp_len == 0 {
            return Err(Status::MissingParameter);
        }
        if f.params.subcommand == 2 {
            Ok(Command::GetKeyAgreement)
        } else {
            Ok(Command::ClientPin(core::mem::replace(
                &mut f.params,
                Parameters::new(),
            )))
        }
    }
}
struct Fields {
    params: Parameters,
    started: bool,
    previous: Option<Key>,
    agreement: super::agreement::Parser,
    key: Option<Option<i8>>,
    cose: bool,
    seen: u16,
    skip_depth: u8,
    body: Option<(i8, usize)>,
}
impl Fields {
    const fn new() -> Self {
        Self {
            params: Parameters::new(),
            started: false,
            previous: None,
            agreement: super::agreement::Parser::new(),
            key: None,
            cose: false,
            seen: 0,
            skip_depth: 0,
            body: None,
        }
    }
    fn event(&mut self, event: Event<'_>) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if self.cose {
            if self
                .agreement
                .event(event, &mut self.params.agreement, Status::InvalidCbor)?
            {
                self.cose = false;
            }
            return Ok(());
        }
        if super::skip_cbor_event(&mut self.skip_depth, event) {
            return Ok(());
        }
        if let Some((key, _)) = self.body {
            let dest: &mut [u8] = match key {
                4 => &mut self.params.auth,
                5 => &mut self.params.new_pin,
                6 => &mut self.params.pin_hash,
                10 => &mut self.params.rp,
                _ => return Err(Status::InvalidCbor),
            };
            super::consume_cbor_body(event, &mut self.body, dest)?;
            return Ok(());
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            let key = Key::ordered(event, &mut self.previous)?;
            self.key = Some(key);
            return Ok(());
        };
        let key = key.unwrap_or(COSE_KEY_MISSING);

        if (1..=6).contains(&key) || key == 9 || key == 10 {
            self.seen |= 1 << key;
        }
        match key {
            1 => match event {
                Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            2 => match event {
                Event::Unsigned(n) => {
                    self.params.subcommand =
                        u8::try_from(n).map_err(|_| Status::InvalidSubcommand)?
                }
                Event::Negative(_) => return Err(Status::InvalidSubcommand),
                _ => return Err(Status::UnexpectedType),
            },
            3 => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.cose = true;
            }
            4..=6 => {
                if self.params.protocol == 0 {
                    return Err(Status::MissingParameter);
                }
                let n = match key {
                    4 => {
                        if self.params.protocol == 1 {
                            16
                        } else {
                            32
                        }
                    }
                    5 => {
                        if self.params.protocol == 1 {
                            64
                        } else {
                            80
                        }
                    }
                    _ => {
                        if self.params.protocol == 1 {
                            16
                        } else {
                            32
                        }
                    }
                };
                self.bytes(key, event, n)?;
            }
            9 => match event {
                Event::Unsigned(n) if n > 0 && n <= 0x3f && n & 8 == 0 => {
                    self.params.permissions = n as u8
                }
                Event::Unsigned(0) => return Err(Status::InvalidParameter),
                Event::Unsigned(_) | Event::Negative(_) => {
                    return Err(Status::UnauthorizedPermission);
                }
                _ => return Err(Status::UnexpectedType),
            },
            10 => match event {
                Event::Text(n) if n > 0 && n <= 254 => {
                    self.params.rp_len = usize::from(n);
                    self.body = Some((10, 0));
                }
                Event::Text(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            _ => self.skip(event),
        }
        Ok(())
    }
    fn bytes(&mut self, key: i8, event: Event<'_>, expected: u16) -> Result<(), Status> {
        match event {
            Event::Bytes(n) if n == expected => {
                self.body = Some((key, 0));
                Ok(())
            }
            Event::Bytes(n) if key == 5 && n > expected => Err(Status::PinPolicy),
            Event::Bytes(_) => Err(Status::InvalidCbor),
            _ => Err(Status::UnexpectedType),
        }
    }
    fn skip(&mut self, event: Event<'_>) {
        if super::is_cbor_container(event) {
            self.skip_depth = 1;
        }
    }
}
