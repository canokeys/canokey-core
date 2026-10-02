// SPDX-License-Identifier: Apache-2.0
//! Shared authenticated envelope. Keep input at its received offsets and
//! authenticate only the exact parameter map, with an in-place prefix.
use super::{Command, Key, Status};
use canokey_protocol::cbor::Event;

pub(super) const PREFIX: usize = 34;
// Keep semantic fields together before the large byte buffer. Thumb-1 can
// address them without rebuilding offsets past the entire request each time.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parameters {
    pub(super) len: usize,
    pub(super) start: usize,
    pub(super) subcommand: u8,
    pub(super) protocol: u8,
    pub(super) auth_len: usize,
    pub(super) minimum: Option<u8>,
    pub(super) force: bool,
    pub(super) rps: [(u16, u16); 4],
    pub(super) rp_count: Option<usize>,
    pub(super) management: super::management::Parsed,
    pub(super) auth: [u8; 32],
    pub(super) message: [u8; PREFIX + super::MAX_REQUEST - 1],
}
impl Parameters {
    const fn new() -> Self {
        Self {
            message: [0; PREFIX + super::MAX_REQUEST - 1],
            len: PREFIX,
            start: 0,
            subcommand: 0,
            protocol: 0,
            auth: [0; 32],
            auth_len: 0,
            minimum: None,
            force: false,
            rps: [(0, 0); 4],
            rp_count: None,
            management: super::management::Parsed::new(),
        }
    }
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
    offset: usize,
}
impl Parser {
    pub const fn new(command: u8) -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::new(),
            fields: Fields::new(command),
            offset: 0,
        }
    }
    // Share this parser across HID and APDU callers on size-constrained targets.
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let f = &mut self.fields;
        let start = PREFIX + self.offset;
        let Some(dest) = f
            .params
            .message
            .get_mut(start..)
            .and_then(|tail| tail.get_mut(..bytes.len()))
        else {
            self.decoder
                .consume(bytes, &mut |_, _| Err(Status::InvalidCbor));
            return;
        };
        dest.copy_from_slice(bytes);
        if !self.decoder.consume(bytes, &mut |event, offset| {
            f.event(event, usize::from(offset))
        }) {
            return;
        }
        self.offset += bytes.len();
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.fields.params.message);
        memory.wipe(&mut self.fields.params.auth);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        // Preserve the legacy bare authenticatorConfig command status.
        if self.fields.command == super::CONFIG && self.offset == 0 {
            return Err(Status::UnhandledRequest);
        }
        self.decoder.finish()?;
        let p = &mut self.fields.params;
        if !self.fields.subcommand_seen {
            return Err(Status::MissingParameter);
        }
        if self.fields.command == super::CONFIG && !matches!(p.subcommand, 2..=4) {
            return Err(Status::InvalidParameter);
        }
        // authenticatorConfig checks auth length here only for a supplied
        // protocol; protocol 0 is left to config.rs to report MissingParameter.
        if self.fields.command == super::CONFIG
            && p.auth_len != 0
            && p.protocol != 0
            && p.auth_len != if p.protocol == 1 { 16 } else { 32 }
        {
            return Err(Status::InvalidParameter);
        }
        // Keep the parameter map at its received offset. The reserved prefix
        // plus the now-dead envelope header provide room for authentication.
        p.start = self.fields.start.unwrap_or(0);
        p.len = PREFIX + self.fields.end.unwrap_or(0);
        let prefix = &mut p.message[p.start..p.start + PREFIX];
        prefix[..32].fill(0xff);
        prefix[32] = super::CONFIG;
        prefix[33] = p.subcommand;
        // Transfer once before choosing the command tag, avoiding a large
        // branch-local temporary with the pinned Thumb-1 compiler.
        let params = self.fields.params;
        // This parser is consumed logically; a second finish must not publish
        // stale metadata. Clear the copied authentication bytes without building
        // another full Parameters value and resetting every semantic field.
        self.clear(&canokey_ports::default_memory());
        self.fields.subcommand_seen = false;
        Ok(if self.fields.command == super::CONFIG {
            Command::Config(params)
        } else {
            Command::Management(params)
        })
    }
}
struct Fields {
    params: Parameters,
    started: bool,
    subcommand_seen: bool,
    command: u8,
    previous: Option<Key>,
    key: Option<Option<i8>>,
    depth: u8,
    auth_offset: Option<usize>,
    start: Option<usize>,
    end: Option<usize>,
    param_key: Option<Option<i8>>,
    param_previous: Option<Key>,
    rp_array: bool,
    management: super::management::Parser,
}
impl Fields {
    const fn new(command: u8) -> Self {
        Self {
            command,
            params: Parameters::new(),
            started: false,
            subcommand_seen: false,
            previous: None,
            key: None,
            depth: 0,
            auth_offset: None,
            start: None,
            end: None,
            param_key: None,
            param_previous: None,
            rp_array: false,
            management: super::management::Parser::new(),
        }
    }
    fn event(&mut self, event: &Event<'_>, offset: usize) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if let Some(pos) = self.auth_offset {
            match *event {
                Event::Data(bytes) => {
                    self.params.auth[pos..pos + bytes.len()].copy_from_slice(bytes);
                    self.auth_offset = Some(pos + bytes.len());
                }
                Event::End => self.auth_offset = None,
                _ => return Err(Status::InvalidCbor),
            }
            return Ok(());
        }
        if self.depth != 0 {
            if self.start.is_some() && self.end.is_none() {
                if self.command == super::CONFIG {
                    self.parameter(event, offset)?;
                } else {
                    self.management.event(
                        &mut self.params.management,
                        &self.params.message,
                        event,
                        self.depth,
                        offset,
                    );
                }
            }
            match *event {
                Event::Map(_) | Event::Array(_) | Event::Bytes(_) | Event::Text(_) => {
                    self.depth += 1
                }
                Event::End => {
                    self.depth -= 1;
                    if self.depth == 0 && self.start.is_some() && self.end.is_none() {
                        self.end = Some(offset);
                    }
                }
                _ => (),
            }
            return Ok(());
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            let key = Key::ordered(event, &mut self.previous)?;
            self.key = Some(key);
            if key == Some(2) {
                self.start = Some(offset);
            }
            return Ok(());
        };
        match key {
            Some(1) => match *event {
                Event::Unsigned(n) => {
                    self.subcommand_seen = true;
                    self.params.subcommand =
                        u8::try_from(n).map_err(|_| Status::InvalidParameter)?
                }
                _ => return Err(Status::UnexpectedType),
            },
            Some(2) => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.depth = 1;
            }
            Some(3) => match *event {
                Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            Some(4) => match *event {
                Event::Bytes(n @ (16 | 32)) => {
                    self.params.auth_len = usize::from(n);
                    self.auth_offset = Some(0);
                }
                Event::Bytes(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            _ => {
                if matches!(
                    event,
                    Event::Map(_) | Event::Array(_) | Event::Bytes(_) | Event::Text(_)
                ) {
                    self.depth = 1;
                }
            }
        }
        Ok(())
    }
    fn parameter(&mut self, event: &Event<'_>, offset: usize) -> Result<(), Status> {
        if self.rp_array && self.depth == 2 {
            match *event {
                Event::Text(n) => {
                    if n > 254 {
                        return Err(Status::InvalidLength);
                    }
                    let count = self.params.rp_count.as_mut().unwrap();
                    self.params.rps[*count] = ((PREFIX + offset) as u16, n);
                    *count += 1;
                }
                Event::End => self.rp_array = false,
                _ => return Err(Status::UnexpectedType),
            }
        }
        if self.depth != 1 {
            return Ok(());
        }
        let Some(key) = self.param_key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            let key = Key::ordered(event, &mut self.param_previous)?;
            self.param_key = Some(key);
            return Ok(());
        };
        match key {
            Some(1) => match *event {
                Event::Unsigned(n) if n <= 63 => self.params.minimum = Some(n as u8),
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            Some(2) => match *event {
                Event::Array(n) if n <= 4 => {
                    self.params.rp_count = Some(0);
                    self.rp_array = true;
                }
                Event::Array(_) => return Err(Status::KeyStoreFull),
                _ => return Err(Status::UnexpectedType),
            },
            Some(3) => match *event {
                Event::Bool(b) => self.params.force = b,
                _ => return Err(Status::UnexpectedType),
            },
            _ => (),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
