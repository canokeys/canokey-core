// SPDX-License-Identifier: Apache-2.0
//! FIDO SELECT, APDU command envelope and response backing. CTAP parsing and
//! execution are shared with native HID in the parent module.
use super::{Request, execute};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

pub const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
const VERSION: &[u8] = b"FIDO_2_0";
const INS_MSG: u8 = 0x10;

pub fn allows_extended(header: Header) -> bool {
    header
        == Header {
            cla: 0x80,
            ins: INS_MSG,
            p1: 0,
            p2: 0,
        }
}

pub struct Applet {
    request: Request,
    response: &'static [u8],
}
impl Applet {
    pub const fn new() -> Self {
        Self {
            request: Request::new(),
            response: &[],
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    pub fn cancel_command(&mut self) {
        // GET RESPONSE abandons input chaining while retaining response backing.
        self.request = Request::new();
    }
    pub fn select(&mut self) -> u32 {
        self.reset();
        self.response = VERSION;
        VERSION.len() as u32
    }
    pub fn begin(&mut self, header: Header) -> Result<(), Sw> {
        self.reset();
        if header.ins != INS_MSG {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        if header.p1 != 0 || header.p2 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        Ok(())
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        self.request.consume(bytes);
        Ok(())
    }
    pub fn finish(&mut self) -> Result<u32, Sw> {
        self.response = execute(core::mem::replace(&mut self.request, Request::new()).finish());
        Ok(self.response.len() as u32)
    }
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), Sw> {
        let end = offset.checked_add(output.len()).ok_or(Sw::WRONG_LENGTH)?;
        output.copy_from_slice(self.response.get(offset..end).ok_or(Sw::WRONG_LENGTH)?);
        Ok(())
    }
    pub fn close(&mut self) {
        self.reset();
    }
}

impl Default for Applet {
    fn default() -> Self {
        Self::new()
    }
}
