// SPDX-License-Identifier: Apache-2.0
//! Wire descriptors; all multibyte fields are explicitly little-endian.
use canokey_protocol::{apdu, ccid, usb::*};
// FIDO page 0xF1D0: 64-byte Input(0x20)/Output(0x21), no report ID.
pub const CTAP_REPORT: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page: FIDO Alliance.
    0x09, 0x01, 0xa1, 0x01, // Usage: authenticator; Application collection.
    0x09, 0x20, // Input report usage.
    0x15, 0x00, 0x26, 0xff, 0x00, // Logical range: 0..255.
    0x75, 0x08, 0x95, 0x40, // 64 eight-bit fields.
    0x81, 0x02, // Input: Data, Variable, Absolute.
    0x09, 0x21, // Output report usage.
    0x15, 0x00, 0x26, 0xff, 0x00, // Logical range: 0..255.
    0x75, 0x08, 0x95, 0x40, // 64 eight-bit fields.
    0x91, 0x02, 0xc0, // Output: Data, Variable, Absolute; End Collection.
];
// Report 1: modifiers, reserved byte, five keys and five LED bits.
// Report 2: relative Consumer usage 0x01AE (AL Keyboard Layout), retained
// from the original descriptor. Runtime's eject report uses usage 0xB8.
pub const KEYBOARD_REPORT: &[u8] = &[
    0x05,
    0x01,
    0x09,
    0x06,
    0xa1,
    0x01, // Generic Desktop/Keyboard collection.
    0x85,
    KEYBOARD_REPORT_ID,
    0x05,
    0x07, // Report1, Keyboard usage page.
    0x19,
    0xe0,
    0x29,
    0xe7, // Modifier usages: Left Control..Right GUI.
    0x15,
    0x00,
    0x25,
    0x01, // Boolean logical range.
    0x75,
    0x01,
    0x95,
    0x08,
    0x81,
    0x02, // Eight modifier bits, Data/Variable.
    0x95,
    0x01,
    0x75,
    0x08,
    0x81,
    0x03, // Reserved constant byte.
    0x95,
    0x05,
    0x75,
    0x01,
    0x05,
    0x08, // Five one-bit LED usages.
    0x19,
    0x01,
    0x29,
    0x05,
    0x91,
    0x02, // Num Lock..Kana, Output/Variable.
    0x95,
    0x01,
    0x75,
    0x03,
    0x91,
    0x03, // Three constant LED padding bits.
    0x95,
    0x05,
    0x75,
    0x08, // Five eight-bit key slots.
    0x15,
    0x00,
    0x25,
    0x65,
    0x05,
    0x07, // Keyboard logical/usage range 0..65.
    0x19,
    0x00,
    0x29,
    0x65,
    0x81,
    0x00,
    0xc0, // Input/Array; End Collection.
    0x05,
    0x0c,
    0x09,
    0x01,
    0xa1,
    0x01, // Consumer Control collection.
    0x85,
    CONSUMER_REPORT_ID, // Report2.
    0x15,
    0x00,
    0x25,
    0x01,
    0x75,
    0x08,
    0x95,
    0x01, // One eight-bit field.
    0x0a,
    0xae,
    0x01,
    0x81,
    0x06,
    0xc0, // Usage01AE, Data/Variable/Relative.
];
pub const DEVICE: &[u8] = &[
    // USB 2.00, per-interface classes, EP0 MPS; VID20A0/PID42D4;
    // Configured bcdDevice, manufacturer/product, no serial, one configuration.
    0x12,
    0x01,
    0x00,
    0x02,
    0x00,
    0x00,
    0x00,
    EP0_PACKET_BYTES as u8,
    0xa0,
    0x20,
    0xd4,
    0x42,
    crate::release::USB_BCD_DEVICE as u8,
    (crate::release::USB_BCD_DEVICE >> 8) as u8,
    STRING_MANUFACTURER,
    STRING_PRODUCT,
    0x00,
    0x01,
];
pub const LANGUAGE: &[u8] = &[0x04, 0x03, 0x09, 0x04]; // LANGID 0x0409 (English US).
pub const CTAP_HID: &[u8] = &[9, 0x21, 0x11, 1, 0, 1, 0x22, CTAP_REPORT.len() as u8, 0];
pub const KEYBOARD_HID: &[u8] = &[9, 0x21, 0x11, 1, 0, 1, 0x22, KEYBOARD_REPORT.len() as u8, 0];

#[derive(Clone, Copy)]
pub struct Interfaces {
    pub hid: bool,
    pub keyboard: bool,
    pub webusb: bool,
}
impl Interfaces {
    pub const fn count(self) -> u8 {
        1 + self.hid as u8 + self.keyboard as u8 + self.webusb as u8
    }
    pub const fn ccid(self) -> u8 {
        self.hid as u8 + self.webusb as u8
    }
    pub const fn webusb(self) -> u8 {
        self.hid as u8
    }
    pub const fn keyboard(self) -> u8 {
        self.ccid() + 1
    }
    pub fn endpoint(self, address: u16) -> bool {
        address & !u16::from(ENDPOINT_ADDRESS_MASK) == 0
            && match address & u16::from(ENDPOINT_NUMBER_MASK) {
                0 => true,
                ep if ep == u16::from(EP_CCID) => true,
                ep if ep == u16::from(EP_KEYBOARD) => self.keyboard,
                ep if ep == u16::from(EP_HID) => self.hid,
                _ => false,
            }
    }
    pub fn hid_interface(self, index: u16) -> Option<usize> {
        if self.hid && index == 0 {
            Some(0)
        } else if self.keyboard && index == self.keyboard() as u16 {
            Some(1)
        } else {
            None
        }
    }
    pub fn configuration(self, out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
        Configuration::new(self).copy_into(out)
    }
}
/// Immutable product composition. Firmware constructs this once in Flash;
/// request handling only reads it and never rebuilds wire descriptors.
pub struct Configuration {
    interfaces: Interfaces,
    bytes: [u8; CONTROL_BUFFER_BYTES],
    length: usize,
}
impl Configuration {
    pub const fn interfaces(&self) -> Interfaces {
        self.interfaces
    }
    pub const fn new(interfaces: Interfaces) -> Self {
        // Configuration9 + CCID interface9 + class54 + two endpoints7.
        const BASE_BYTES: usize = 9 + 9 + 54 + 2 * 7;
        // HID interface9 + HID9 + two endpoints7; WebUSB has one interface9.
        const HID_BYTES: usize = 9 + 9 + 2 * 7;
        const WEBUSB_BYTES: usize = 9;
        let length = BASE_BYTES
            + HID_BYTES * (interfaces.hid as usize + interfaces.keyboard as usize)
            + WEBUSB_BYTES * interfaces.webusb as usize;
        let mut descriptor = Self {
            interfaces,
            bytes: [0; CONTROL_BUFFER_BYTES],
            length: 0,
        };
        // Bus-powered, bMaxPower=50 units of 2 mA (100 mA).
        descriptor.append(&[9, 2, length as u8, 0, interfaces.count(), 1, 0, 0x80, 50]);
        if interfaces.hid {
            // HID interface, two interrupt endpoints: MPS64, interval5 ms.
            descriptor.append(&[9, 4, 0, 0, 2, 3, 0, 0, 0]);
            descriptor.append(CTAP_HID);
            descriptor.append(&[
                7,
                5,
                EP_HID_IN,
                3,
                DATA_PACKET_BYTES as u8,
                0,
                5,
                7,
                5,
                EP_HID,
                3,
                DATA_PACKET_BYTES as u8,
                0,
                5,
            ]);
        }
        if interfaces.webusb {
            // Vendor class/subclass/protocol FF; no non-control endpoint.
            descriptor.append(&[
                9,
                4,
                interfaces.webusb(),
                0,
                0,
                0xff,
                0xff,
                0xff,
                STRING_WEBUSB,
            ]);
        }
        descriptor.append(&[9, 4, interfaces.ccid(), 0, 2, 0x0b, 0, 0, 0]);
        let max: u16 = if interfaces.hid {
            ccid::HEADER as u16
                + apdu::EXTENDED_OVERHEAD_BYTES as u16
                + canokey_protocol::ctaphid::CTAP_MAX_REQUEST as u16
        } else {
            ccid::HEADER as u16 + apdu::SHORT_FRAME_BYTES as u16
        };
        // CCID1.10: one slot, 5V/3V/1.8V, T=1, clock4 MHz, baud307200,
        // dwMaxIFSD261, automatic parameter/clock/baud/voltage negotiation.
        // dwFeatures=0x000400FE (extended APDU) with HID, else 0x000200FE
        // (short APDU); GET RESPONSE/ENVELOPE class=0xFF.
        descriptor.append(&[
            0x36,
            0x21,
            0x10,
            0x01, // Length54, CCID type, bcdCCID1.10.
            0x00,
            0x07, // Max slot0; 5V/3V/1.8V supported.
            0x02,
            0x00,
            0x00,
            0x00, // dwProtocols: T=1.
            0xa0,
            0x0f,
            0x00,
            0x00, // Default clock4000 kHz.
            0xa0,
            0x0f,
            0x00,
            0x00, // Maximum clock4000 kHz.
            0x00, // No explicit supported-clock table.
            0x00,
            0xb0,
            0x04,
            0x00, // Default data rate307200 bps.
            0x00,
            0xb0,
            0x04,
            0x00, // Maximum data rate307200 bps.
            0x00, // No explicit supported-data-rate table.
            0x05,
            0x01,
            0x00,
            0x00, // dwMaxIFSD261.
            0x00,
            0x00,
            0x00,
            0x00, // No synchronous protocols.
            0x00,
            0x00,
            0x00,
            0x00, // No mechanical features.
            0xfe,
            0x00,
            if interfaces.hid { 0x04 } else { 0x02 },
            0x00, // dwFeatures.
            max as u8,
            (max >> 8) as u8,
            0x00,
            0x00, // dwMaxCCIDMessageLength.
            0xff,
            0xff, // bClassGetResponse / bClassEnvelope.
            0x00,
            0x00, // wLcdLayout: no display.
            0x00,
            0x01, // No PIN-pad verification; one busy slot.
        ]);
        // CCID bulk IN/OUT, MPS64; bInterval unused for bulk endpoints.
        descriptor.append(&[
            7,
            5,
            EP_CCID_IN,
            2,
            DATA_PACKET_BYTES as u8,
            0,
            0,
            7,
            5,
            EP_CCID,
            2,
            DATA_PACKET_BYTES as u8,
            0,
            0,
        ]);
        if interfaces.keyboard {
            descriptor.append(&[9, 4, interfaces.keyboard(), 0, 2, 3, 0, 0, 0]);
            descriptor.append(KEYBOARD_HID);
            descriptor.append(&[
                7,
                5,
                EP_KEYBOARD_IN,
                3,
                KEYBOARD_PACKET_BYTES as u8,
                0,
                5,
                7,
                5,
                EP_KEYBOARD,
                3,
                KEYBOARD_PACKET_BYTES as u8,
                0,
                5,
            ]);
        }
        assert!(descriptor.length == length);
        descriptor
    }
    const fn append(&mut self, bytes: &[u8]) {
        let mut index = 0;
        while index < bytes.len() {
            self.bytes[self.length] = bytes[index];
            self.length += 1;
            index += 1;
        }
    }
    pub fn copy_into(&self, out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
        out[..self.length].copy_from_slice(&self.bytes[..self.length]);
        self.length
    }
}
pub fn string(text: &[u8], out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
    let n = text.len().min((CONTROL_BUFFER_BYTES - 2) / 2);
    out[0] = (2 + 2 * n) as u8;
    out[1] = 3;
    for (i, ch) in text[..n].iter().enumerate() {
        out[2 + 2 * i] = *ch;
        out[3 + 2 * i] = 0;
    }
    2 + 2 * n
}
