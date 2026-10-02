// SPDX-License-Identifier: Apache-2.0
//! USB SETUP wire representation, independent of native layout and endianness.
#![forbid(unsafe_code)]
// Product endpoint ABI, shared by descriptors, firmware DCD and host shim.
pub const EP_KEYBOARD: u8 = 0x01;
pub const EP_HID: u8 = 0x02;
pub const EP_CCID: u8 = 0x03;
pub const DIRECTION_IN: u8 = 0x80;
pub const EP_KEYBOARD_IN: u8 = DIRECTION_IN | EP_KEYBOARD;
pub const EP_HID_IN: u8 = DIRECTION_IN | EP_HID;
pub const EP_CCID_IN: u8 = DIRECTION_IN | EP_CCID;
pub const ENDPOINT_NUMBER_MASK: u8 = 0x7f;
pub const ENDPOINT_ADDRESS_MASK: u8 = DIRECTION_IN | EP_CCID;
pub const EP0_PACKET_BYTES: usize = 16;
pub const KEYBOARD_PACKET_BYTES: usize = 8;
pub const DATA_PACKET_BYTES: usize = 64;
pub const CONTROL_BUFFER_BYTES: usize = 160; // Maximum configuration is 159 bytes.
pub const KEYBOARD_REPORT_ID: u8 = 0x01;
pub const CONSUMER_REPORT_ID: u8 = 0x02;
pub const CONSUMER_REPORT_BYTES: usize = 2;
pub const KEYBOARD_LED_MASK: u8 = 0x1f;
// PASS output ABI: ASCII ETX requests Consumer Eject rather than typing a key.
pub const EJECT_SENTINEL: u8 = 0x03;
pub const GET_STATUS: u8 = 0x00;
pub const CLEAR_FEATURE: u8 = 0x01;
pub const SET_FEATURE: u8 = 0x03;
pub const SET_ADDRESS: u8 = 0x05;
pub const GET_DESCRIPTOR: u8 = 0x06;
pub const GET_CONFIGURATION: u8 = 0x08;
pub const HID_SET_REPORT: u8 = 0x09;
pub const SET_CONFIGURATION: u8 = 0x09;
pub const GET_INTERFACE: u8 = 0x0a;
pub const SET_INTERFACE: u8 = 0x0b;
pub const HID_GET_IDLE: u8 = 0x02;
pub const HID_SET_IDLE: u8 = 0x0a;
pub const DEVICE_IN: u8 = 0x80;
pub const DEVICE_OUT: u8 = 0x00;
pub const INTERFACE_IN: u8 = 0x81;
pub const INTERFACE_OUT: u8 = 0x01;
pub const ENDPOINT_IN: u8 = 0x82;
pub const ENDPOINT_OUT: u8 = 0x02;
pub const CLASS_INTERFACE_IN: u8 = 0xa1;
pub const CLASS_INTERFACE_OUT: u8 = 0x21;
pub const VENDOR_INTERFACE_OUT: u8 = 0x41;
pub const VENDOR_INTERFACE_IN: u8 = 0xc1;
pub const STRING_MANUFACTURER: u8 = 0x01;
pub const STRING_PRODUCT: u8 = 0x02;
pub const STRING_WEBUSB: u8 = 0x12;
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
