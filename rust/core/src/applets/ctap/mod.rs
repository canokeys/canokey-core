// SPDX-License-Identifier: Apache-2.0
//! Development CTAP slice: discovery only, no credential operations yet.
#![forbid(unsafe_code)]

pub mod apdu;

const GET_INFO: u8 = 0x04;
pub const MAX_REQUEST: usize = 1024;
// Status, then GetInfo: versions, development AAGUID, options, maxMsgSize,
// transports. Do not advertise PIN protocols, algorithms or resident keys
// until their handlers exist. This profile is not a usable authenticator yet.
#[rustfmt::skip]
const INFO: &[u8] = &[
    0x00, 0xa5, // Success, five-field map
    0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0',
    0x03, 0x50, // AAGUID: 16 bytes
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x04, 0xa2, 0x62, b'r', b'k', 0xf4, 0x62, b'u', b'p', 0xf4,
    0x05, 0x19, 0x04, 0x00, // maxMsgSize: 1024
    0x09, 0x81, 0x63, b'u', b's', b'b',
];

/// Only owned semantic state crosses this boundary. Request storage is already
/// closed by the caller, so later handlers may safely wait or invoke crypto.
pub fn execute(command: Result<Command, Status>) -> &'static [u8] {
    match command {
        Ok(Command::GetInfo) => INFO,
        Err(Status::InvalidLength) => &[0x03],
        Err(Status::InvalidCommand) => &[0x01],
    }
}

pub enum Command {
    GetInfo,
}
pub enum Status {
    InvalidLength,
    InvalidCommand,
}

pub struct Request {
    command: Option<u8>,
    extra: bool,
}
impl Request {
    pub const fn new() -> Self {
        Self {
            command: None,
            extra: false,
        }
    }
    pub fn consume(&mut self, mut bytes: &[u8]) {
        if self.command.is_none() {
            self.command = bytes.first().copied();
            bytes = bytes.get(1..).unwrap_or_default();
        }
        // Discovery has no parameters. Future schemas consume fragments here,
        // retaining semantic fields rather than a copy of the request.
        self.extra |= !bytes.is_empty();
    }
    pub fn finish(self) -> Result<Command, Status> {
        match self.command {
            None => Err(Status::InvalidLength),
            Some(GET_INFO) if !self.extra => Ok(Command::GetInfo),
            Some(GET_INFO) => Err(Status::InvalidLength),
            _ => Err(Status::InvalidCommand),
        }
    }
}
