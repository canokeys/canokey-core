// SPDX-License-Identifier: Apache-2.0
//! Wire descriptors; all multibyte fields are explicitly little-endian.
use canokey_protocol::{apdu, ccid, usb::*};
use canokey_transport_runtime::usb::descriptors as common;
pub use canokey_transport_runtime::usb::{CTAP_HID, CTAP_REPORT, LANGUAGE};
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
pub const DEVICE: &[u8] = &common::device(
    0x20a0,
    0x42d4,
    crate::release::USB_BCD_DEVICE,
    EP0_PACKET_BYTES as u8,
    0x00,
);

pub const KEYBOARD_HID: &[u8] = &[9, 0x21, 0x11, 1, 0, 1, 0x22, KEYBOARD_REPORT.len() as u8, 0];

#[derive(Clone, Copy)]
pub struct Interfaces {
    pub hid: bool,
    pub keyboard: bool,
    pub webusb: bool,
}
impl Interfaces {
    pub const fn count(self) -> u8 {
        self.composition().count()
    }
    pub const fn ccid(self) -> u8 {
        self.composition().ccid()
    }
    pub const fn webusb(self) -> u8 {
        self.composition().webusb()
    }
    pub const fn keyboard(self) -> u8 {
        self.composition().keyboard()
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
    const fn composition(self) -> common::Composition {
        common::Composition {
            ctap: if self.hid {
                Some(common::Endpoints {
                    input: EP_HID_IN,
                    output: EP_HID,
                    packet_bytes: DATA_PACKET_BYTES as u16,
                })
            } else {
                None
            },
            webusb_string: if self.webusb {
                Some(STRING_WEBUSB)
            } else {
                None
            },
            ccid: common::Endpoints {
                input: EP_CCID_IN,
                output: EP_CCID,
                packet_bytes: DATA_PACKET_BYTES as u16,
            },
            maximum_ccid_message_bytes: (ccid::HEADER + apdu::SHORT_FRAME_BYTES) as u16,
            keyboard: if self.keyboard {
                Some(common::Hid {
                    descriptor: KEYBOARD_HID,
                    endpoints: common::Endpoints {
                        input: EP_KEYBOARD_IN,
                        output: EP_KEYBOARD,
                        packet_bytes: KEYBOARD_PACKET_BYTES as u16,
                    },
                })
            } else {
                None
            },
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
    descriptor: common::Configuration<CONTROL_BUFFER_BYTES>,
}
impl Configuration {
    pub const fn interfaces(&self) -> Interfaces {
        self.interfaces
    }
    pub const fn new(interfaces: Interfaces) -> Self {
        Self {
            interfaces,
            descriptor: common::Configuration::new(interfaces.composition()),
        }
    }
    pub fn copy_into(&self, out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
        self.descriptor.copy_into(out)
    }
}

pub fn string(text: &[u8], out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
    canokey_transport_runtime::usb::string(text, out)
}
