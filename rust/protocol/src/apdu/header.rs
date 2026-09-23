// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}

impl Header {
    pub fn is_get_response(self) -> bool {
        matches!(self.cla, 0x00 | 0x80) && self.ins == 0xc0
    }

    pub fn chained(self) -> bool {
        self.cla & 0x10 != 0
    }

    pub fn unchained(self) -> Self {
        Self {
            cla: self.cla & !0x10,
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Consumer,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandInfo {
    pub header: Header,
    pub lc: u16,
    /// None means Le is absent on the wire. Zero encodings are expanded.
    pub le: Option<u32>,
    pub extended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command<'a> {
    pub info: CommandInfo,
    pub data: &'a [u8],
}
