// SPDX-License-Identifier: Apache-2.0
//! USB SETUP wire representation, independent of native layout and endianness.
#![forbid(unsafe_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    pub kind: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}
impl Setup {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 {
            return None;
        }
        Some(Self {
            kind: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        })
    }
}
