// SPDX-License-Identifier: Apache-2.0
//! Shared authenticated subcommand envelope; preserve only the exact parameter map.
use super::{Command, Key, Status};
use canokey_protocol::cbor::{self, Event};

pub(super) const PREFIX: usize = 34;
pub struct Parameters {
    pub(super) message: [u8; PREFIX + super::MAX_REQUEST - 1],
    pub(super) len: usize,
    pub(super) subcommand: u8,
    pub(super) protocol: u8,
    pub(super) auth: [u8; 32],
    pub(super) auth_len: usize,
    pub(super) minimum: Option<u8>,
    pub(super) force: bool,
    pub(super) rps: [(u16, u16); 4],
    pub(super) rp_count: Option<usize>,
}
impl Parameters {
    const fn new() -> Self {
        Self {
            message: [0; PREFIX + super::MAX_REQUEST - 1],
            len: PREFIX,
            subcommand: 0,
            protocol: 0,
            auth: [0; 32],
            auth_len: 0,
            minimum: None,
            force: false,
            rps: [(0, 0); 4],
            rp_count: None,
        }
    }
}
pub struct Parser {
    decoder: cbor::Decoder,
    fields: Fields,
    offset: usize,
    error: Option<Status>,
}
impl Parser {
    pub const fn new(command: u8) -> Self {
        Self {
            decoder: cbor::Decoder::new((super::MAX_REQUEST - 1) as u16),
            fields: Fields::new(command),
            offset: 0,
            error: None,
        }
    }
    pub fn consume(&mut self, bytes: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let f = &mut self.fields;
        let error = &mut self.error;
        if self
            .decoder
            .feed_at(bytes, &mut |event, offset| {
                f.event(event, usize::from(offset)).map_err(|status| {
                    *error = Some(status);
                    cbor::Error::Consumer
                })
            })
            .is_err()
        {
            error.get_or_insert(Status::InvalidCbor);
            return;
        }
        // Only the authenticated parameter map crosses the source lifetime.
        // Offsets include split headers and empty maps, without re-encoding.
        if let Some(start) = f.start {
            let from = start.max(self.offset);
            let to = f
                .end
                .unwrap_or(self.offset + bytes.len())
                .min(self.offset + bytes.len());
            if from < to {
                let dest = PREFIX + from - start;
                f.params.message[dest..dest + to - from]
                    .copy_from_slice(&bytes[from - self.offset..to - self.offset]);
                f.params.len = dest + to - from;
            }
        }
        self.offset += bytes.len();
    }
    pub(crate) fn clear(&mut self, memory: &dyn crate::ports::Memory) {
        memory.wipe(&mut self.fields.params.message);
        memory.wipe(&mut self.fields.params.auth);
    }
    pub fn finish(mut self) -> Result<Command, Status> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.decoder.finish().map_err(|_| Status::InvalidCbor)?;
        let p = &mut self.fields.params;
        if !self.fields.subcommand_seen {
            return Err(Status::MissingParameter);
        }
        if self.fields.command == super::CONFIG && !matches!(p.subcommand, 2..=4) {
            return Err(Status::InvalidParameter);
        }
        if p.auth_len != 0 && p.protocol != 0 && p.auth_len != if p.protocol == 1 { 16 } else { 32 }
        {
            return Err(Status::InvalidParameter);
        }
        p.message[..32].fill(0xff);
        p.message[32] = super::CONFIG;
        p.message[33] = p.subcommand;
        Ok(if self.fields.command == super::CONFIG {
            Command::Config(self.fields.params)
        } else {
            Command::Management(self.fields.params)
        })
    }
}
struct Fields {
    params: Parameters,
    started: bool,
    subcommand_seen: bool,
    command: u8,
    previous: Option<Key>,
    key: Option<Key>,
    depth: u8,
    auth_offset: Option<usize>,
    start: Option<usize>,
    end: Option<usize>,
    param_key: Option<Key>,
    param_previous: Option<Key>,
    rp_array: bool,
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
        }
    }
    fn event(&mut self, event: Event<'_>, offset: usize) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if let Some(pos) = self.auth_offset {
            match event {
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
            if self.command == super::CONFIG && self.start.is_some() && self.end.is_none() {
                self.parameter(&event, offset)?;
            }
            match event {
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
            let key = Key::parse(event)?;
            if self.previous.is_some_and(|old| key <= old) {
                return Err(Status::InvalidCbor);
            }
            self.previous = Some(key);
            self.key = Some(key);
            if key.integer() == Some(2) {
                self.start = Some(offset);
            }
            return Ok(());
        };
        match key.integer() {
            Some(1) => match event {
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
            Some(3) => match event {
                Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            Some(4) => match event {
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
                    self.params.rps[*count] = ((PREFIX + offset - self.start.unwrap()) as u16, n);
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
            let key = match *event {
                Event::Unsigned(n) => Key::parse(Event::Unsigned(n))?,
                Event::Negative(n) => Key::parse(Event::Negative(n))?,
                _ => return Err(Status::UnexpectedType),
            };
            if self.param_previous.is_some_and(|old| key <= old) {
                return Err(Status::InvalidCbor);
            }
            self.param_previous = Some(key);
            self.param_key = Some(key);
            return Ok(());
        };
        match key.integer() {
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
