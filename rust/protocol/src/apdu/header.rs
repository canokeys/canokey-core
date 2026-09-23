// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}

const CLA_ISO: u8 = 0x00;
const CLA_PROPRIETARY: u8 = 0x80;
const CLA_CHAINING: u8 = 0x10;
const INS_SELECT: u8 = 0xa4;
const INS_GET_RESPONSE: u8 = 0xc0;
const SELECT_BY_NAME: u8 = 0x04;
impl Header {
    pub fn is_select_by_name(self) -> bool {
        self.cla == CLA_ISO && self.ins == INS_SELECT && self.p1 == SELECT_BY_NAME
    }

    pub fn is_get_response(self) -> bool {
        matches!(self.cla, CLA_ISO | CLA_PROPRIETARY) && self.ins == INS_GET_RESPONSE
    }

    pub fn chained(self) -> bool {
        self.cla & CLA_CHAINING != 0
    }

    pub fn unchained(self) -> Self {
        Self {
            cla: self.cla & !CLA_CHAINING,
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
    /// Final parse/finish: None means absent; zero encodings are expanded.
    /// FrameEvent::Start always reports None because trailing Le may be unread.
    pub le: Option<u32>,
    pub extended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command<'a> {
    pub info: CommandInfo,
    pub data: &'a [u8],
}
