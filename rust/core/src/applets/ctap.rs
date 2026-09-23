// SPDX-License-Identifier: Apache-2.0
//! Stateless CCID CTAP `authenticatorGetInfo` slice.
#![forbid(unsafe_code)]

use crate::Platform;
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

pub const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
pub const INS_MSG: u8 = 0x10;
pub const GET_INFO: u8 = 0x04;
const RESPONSE: &[u8] = &[
    0x00, 0xa5, 0x01, 0x81, 0x6a, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0', 0x03, 0x81, 0x63,
    b'u', b's', b'b', 0x04, 0x19, 0x04, 0x00, 0x05, 0x81, 0x01,
];

pub struct Ctap {
    command: Option<u8>,
    response: [u8; RESPONSE.len()],
}
impl Ctap {
    pub const fn new() -> Self {
        Self {
            command: None,
            response: [0; RESPONSE.len()],
        }
    }
    pub fn reset(&mut self) {
        self.command = None;
        self.response.fill(0);
    }
    pub fn begin(&mut self, header: Header) -> Result<(), Sw> {
        if header.ins != INS_MSG {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        self.command = None;
        Ok(())
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        if bytes.len() != 1 || self.command.is_some() {
            return Err(Sw::WRONG_LENGTH);
        }
        self.command = Some(bytes[0]);
        Ok(())
    }
    pub fn finish(&mut self) -> Result<u32, Sw> {
        if self.command != Some(GET_INFO) {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        self.response.copy_from_slice(RESPONSE);
        Ok(RESPONSE.len() as u32)
    }
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), Sw> {
        let end = offset.checked_add(output.len()).ok_or(Sw::WRONG_LENGTH)?;
        output.copy_from_slice(self.response.get(offset..end).ok_or(Sw::WRONG_LENGTH)?);
        Ok(())
    }
    pub fn close(&mut self) {
        self.reset();
    }
    pub fn install(&mut self, _p: &mut Platform<'_>) {}
}
impl Default for Ctap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_is_a_fixed_ram_response() {
        let mut ctap = Ctap::new();
        ctap.consume(&[GET_INFO]).unwrap();
        let length = ctap.finish().unwrap() as usize;
        let mut response = [0; RESPONSE.len()];
        ctap.read(0, &mut response).unwrap();
        assert_eq!(length, RESPONSE.len());
        assert_eq!(&response, RESPONSE);
        ctap.close();
        assert!(ctap.consume(&[GET_INFO]).is_ok());
    }
}
