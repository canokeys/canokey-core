// SPDX-License-Identifier: Apache-2.0
//! Wire descriptors; all multibyte fields are explicitly little-endian.
pub const CTAP_REPORT: &[u8] = &[
    0x6, 0xd0, 0xf1, 0x9, 0x1, 0xa1, 0x1, 0x9, 0x20, 0x15, 0x0, 0x26, 0xff, 0x0, 0x75, 0x8, 0x95,
    0x40, 0x81, 0x2, 0x9, 0x21, 0x15, 0x0, 0x26, 0xff, 0x0, 0x75, 0x8, 0x95, 0x40, 0x91, 0x2, 0xc0,
];
pub const KEYBOARD_REPORT: &[u8] = &[
    0x5, 0x1, 0x9, 0x6, 0xa1, 0x1, 0x85, 0x1, 0x5, 0x7, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x0, 0x25,
    0x1, 0x75, 0x1, 0x95, 0x8, 0x81, 0x2, 0x95, 0x1, 0x75, 0x8, 0x81, 0x3, 0x95, 0x5, 0x75, 0x1,
    0x5, 0x8, 0x19, 0x1, 0x29, 0x5, 0x91, 0x2, 0x95, 0x1, 0x75, 0x3, 0x91, 0x3, 0x95, 0x5, 0x75,
    0x8, 0x15, 0x0, 0x25, 0x65, 0x5, 0x7, 0x19, 0x0, 0x29, 0x65, 0x81, 0x0, 0xc0, 0x5, 0xc, 0x9,
    0x1, 0xa1, 0x1, 0x85, 0x2, 0x15, 0x0, 0x25, 0x1, 0x75, 0x8, 0x95, 0x1, 0xa, 0xae, 0x1, 0x81,
    0x6, 0xc0,
];
pub const DEVICE: &[u8] = &[
    18, 1, 0, 2, 0, 0, 0, 16, 0xa0, 0x20, 0xd4, 0x42, 0, 1, 1, 2, 0, 1,
];
pub const LANGUAGE: &[u8] = &[4, 3, 9, 4];
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
        address & !0x83 == 0
            && match address & 0x7f {
                0 | 3 => true,
                1 => self.keyboard,
                2 => self.hid,
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
    pub fn configuration(self, out: &mut [u8; 160]) -> usize {
        Configuration::new(self).copy_into(out)
    }
}
/// Immutable product composition. Firmware constructs this once in Flash;
/// request handling only reads it and never rebuilds wire descriptors.
pub struct Configuration {
    interfaces: Interfaces,
    bytes: [u8; 160],
    length: usize,
}
impl Configuration {
    pub const fn interfaces(&self) -> Interfaces {
        self.interfaces
    }
    pub const fn new(interfaces: Interfaces) -> Self {
        let length = 86
            + 32 * (interfaces.hid as usize + interfaces.keyboard as usize)
            + 9 * interfaces.webusb as usize;
        let mut descriptor = Self {
            interfaces,
            bytes: [0; 160],
            length: 0,
        };
        descriptor.append(&[9, 2, length as u8, 0, interfaces.count(), 1, 0, 0x80, 50]);
        if interfaces.hid {
            descriptor.append(&[9, 4, 0, 0, 2, 3, 0, 0, 0]);
            descriptor.append(CTAP_HID);
            descriptor.append(&[7, 5, 0x82, 3, 64, 0, 5, 7, 5, 2, 3, 64, 0, 5]);
        }
        if interfaces.webusb {
            descriptor.append(&[9, 4, interfaces.webusb(), 0, 0, 0xff, 0xff, 0xff, 0x12]);
        }
        descriptor.append(&[9, 4, interfaces.ccid(), 0, 2, 0x0b, 0, 0, 0]);
        let max: u16 = if interfaces.hid {
            10 + 7 + 1024 + 2
        } else {
            271
        };
        descriptor.append(&[
            54,
            0x21,
            0x10,
            1,
            0,
            7,
            2,
            0,
            0,
            0,
            0xa0,
            0x0f,
            0,
            0,
            0xa0,
            0x0f,
            0,
            0,
            0,
            0,
            0xb0,
            4,
            0,
            0,
            0xb0,
            4,
            0,
            0,
            5,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0xfe,
            0,
            if interfaces.hid { 4 } else { 2 },
            0,
            max as u8,
            (max >> 8) as u8,
            0,
            0,
            0xff,
            0xff,
            0,
            0,
            0,
            1,
        ]);
        descriptor.append(&[7, 5, 0x83, 2, 64, 0, 0, 7, 5, 3, 2, 64, 0, 0]);
        if interfaces.keyboard {
            descriptor.append(&[9, 4, interfaces.keyboard(), 0, 2, 3, 0, 0, 0]);
            descriptor.append(KEYBOARD_HID);
            descriptor.append(&[7, 5, 0x81, 3, 8, 0, 5, 7, 5, 1, 3, 8, 0, 5]);
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
    pub fn copy_into(&self, out: &mut [u8; 160]) -> usize {
        out[..self.length].copy_from_slice(&self.bytes[..self.length]);
        self.length
    }
}
pub fn string(text: &[u8], out: &mut [u8; 160]) -> usize {
    let n = text.len().min(79);
    out[0] = (2 + 2 * n) as u8;
    out[1] = 3;
    for (i, ch) in text[..n].iter().enumerate() {
        out[2 + 2 * i] = *ch;
        out[3 + 2 * i] = 0;
    }
    2 + 2 * n
}
