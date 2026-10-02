// SPDX-License-Identifier: Apache-2.0
//! USB control policy. IRQ-local USB state never borrows applet or session state.
#![forbid(unsafe_code)]
pub mod descriptors;
pub mod webusb;
use canokey_protocol::usb::*;
use descriptors::{Configuration, Interfaces};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Data(usize),
    Descriptor(webusb::Descriptor),
    Status,
    Address(u8),
    Configure(bool),
    Interface(u8),
    Halt(u8, bool),
    ReceiveLed,
    Stall,
}
pub struct Device {
    pub address: u8,
    pub configured: bool,
    idle: [u8; 2],
    pub leds: u8,
    pub landing: bool,
}
impl Device {
    pub const fn new() -> Self {
        Self {
            address: 0,
            configured: false,
            idle: [0; 2],
            leds: 0,
            landing: true,
        }
    }
    pub fn reset(&mut self) {
        let landing = self.landing;
        *self = Self::new();
        self.landing = landing;
    }
    pub fn setup(
        &mut self,
        configuration: &Configuration,
        s: Setup,
        stalled: bool,
        out: &mut [u8; CONTROL_BUFFER_BYTES],
    ) -> Reply {
        let interfaces = configuration.interfaces();
        if interfaces.webusb {
            if let Some(d) = webusb::Descriptor::request(s, interfaces.webusb()) {
                return Reply::Descriptor(if d == webusb::Descriptor::Bos && !self.landing {
                    webusb::Descriptor::BosWithoutLanding
                } else {
                    d
                });
            }
        }
        let zero = s.value == 0 && s.index == 0;
        match (s.kind, s.request) {
            (DEVICE_IN, GET_DESCRIPTOR) if s.value as u8 == 0 && s.index == 0 => {
                let desc = match s.value >> 8 {
                    1 => descriptors::DEVICE,
                    2 => return Reply::Data(configuration.copy_into(out)),
                    3 => descriptors::LANGUAGE,
                    _ => return Reply::Stall,
                };
                out[..desc.len()].copy_from_slice(desc);
                if s.value >> 8 == 1 && interfaces.webusb {
                    // WebUSB BOS platform capabilities require bcdUSB 2.10.
                    out[2] = 0x10;
                }
                Reply::Data(desc.len())
            }
            (DEVICE_IN, GET_DESCRIPTOR)
                if s.value >> 8 == 3 && (s.index == 0 || s.index == 0x409) =>
            {
                let text: &[u8] = match s.value as u8 {
                    STRING_MANUFACTURER => b"canokeys.org",
                    STRING_PRODUCT => b"CanoKey Rust Core",
                    STRING_WEBUSB if interfaces.webusb => b"WebUSB",
                    _ => return Reply::Stall,
                };
                Reply::Data(descriptors::string(text, out))
            }
            (DEVICE_OUT, SET_ADDRESS)
                if s.index == 0 && s.length == 0 && s.value <= 127 && !self.configured =>
            {
                Reply::Address(s.value as u8)
            }
            (DEVICE_OUT, SET_CONFIGURATION)
                if s.index == 0 && s.length == 0 && s.value <= 1 && self.address != 0 =>
            {
                Reply::Configure(s.value != 0)
            }
            (DEVICE_IN, GET_CONFIGURATION) if zero && s.length == 1 && self.address != 0 => {
                out[0] = self.configured as u8;
                Reply::Data(1)
            }
            (DEVICE_IN, GET_STATUS) if zero && s.length == 2 => {
                out[..2].fill(0);
                Reply::Data(2)
            }
            (INTERFACE_IN, GET_STATUS)
                if self.configured
                    && s.index < interfaces.count() as u16
                    && s.value == 0
                    && s.length == 2 =>
            {
                out[..2].fill(0);
                Reply::Data(2)
            }
            (INTERFACE_IN, GET_INTERFACE)
                if self.configured
                    && s.index < interfaces.count() as u16
                    && s.value == 0
                    && s.length == 1 =>
            {
                out[0] = 0;
                Reply::Data(1)
            }
            (INTERFACE_OUT, SET_INTERFACE)
                if self.configured
                    && s.index < interfaces.count() as u16
                    && s.value == 0
                    && s.length == 0 =>
            {
                Reply::Interface(s.index as u8)
            }
            (ENDPOINT_IN, GET_STATUS)
                if s.value == 0 && s.length == 2 && self.valid_endpoint(interfaces, s.index) =>
            {
                out[0] = stalled as u8;
                out[1] = 0;
                Reply::Data(2)
            }
            (ENDPOINT_OUT, CLEAR_FEATURE | SET_FEATURE)
                if self.configured
                    && s.value == 0
                    && s.length == 0
                    && self.valid_endpoint(interfaces, s.index)
                    && s.index & 0x7f != 0 =>
            {
                Reply::Halt(s.index as u8, s.request == SET_FEATURE)
            }
            _ => self.hid(interfaces, s, out),
        }
    }
    fn valid_endpoint(&self, interfaces: Interfaces, endpoint: u16) -> bool {
        interfaces.endpoint(endpoint) && (endpoint & 0x7f == 0 || self.configured)
    }
    fn hid(
        &mut self,
        interfaces: Interfaces,
        s: Setup,
        out: &mut [u8; CONTROL_BUFFER_BYTES],
    ) -> Reply {
        if !self.configured {
            return Reply::Stall;
        }
        let Some(hid) = interfaces.hid_interface(s.index) else {
            return Reply::Stall;
        };
        match (s.kind, s.request) {
            (INTERFACE_IN, GET_DESCRIPTOR) if s.value as u8 == 0 => {
                let bytes = match (hid, s.value >> 8) {
                    (0, 0x21) => descriptors::CTAP_HID,
                    (0, 0x22) => descriptors::CTAP_REPORT,
                    (1, 0x21) => descriptors::KEYBOARD_HID,
                    (1, 0x22) => descriptors::KEYBOARD_REPORT,
                    _ => return Reply::Stall,
                };
                out[..bytes.len()].copy_from_slice(bytes);
                Reply::Data(bytes.len())
            }
            (CLASS_INTERFACE_OUT, HID_SET_IDLE)
                if s.length == 0 && (s.value as u8 == 0 || (hid == 1 && s.value as u8 <= 2)) =>
            {
                self.idle[hid] = (s.value >> 8) as u8;
                Reply::Status
            }
            (CLASS_INTERFACE_IN, HID_GET_IDLE)
                if s.length == 1 && (s.value == 0 || (hid == 1 && s.value <= 2)) =>
            {
                out[0] = self.idle[hid];
                Reply::Data(1)
            }
            // Keyboard LEDs, report ID 1. HID protocol is report-only: the
            // interface does not advertise boot protocol or remote wakeup.
            (CLASS_INTERFACE_OUT, HID_SET_REPORT)
                if hid == 1 && s.value == 0x0201 && s.length == 2 =>
            {
                Reply::ReceiveLed
            }
            _ => Reply::Stall,
        }
    }
}
impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}
/// One control-IN transaction. Count acknowledgements, not submitted packets.
/// Exact host length never sends an extra ZLP; a shorter MPS multiple does.
pub struct ControlIn {
    total: usize,
    offset: usize,
    zlp: bool,
}
impl ControlIn {
    pub const fn new() -> Self {
        Self {
            total: 0,
            offset: 0,
            zlp: false,
        }
    }
    pub fn begin(&mut self, available: usize, requested: u16) {
        self.total = available.min(requested as usize);
        self.offset = 0;
        self.zlp = self.total < requested as usize && self.total % EP0_PACKET_BYTES == 0;
    }
    pub fn next_packet(&mut self) -> Option<(usize, usize)> {
        if self.offset < self.total {
            let n = (self.total - self.offset).min(EP0_PACKET_BYTES);
            let start = self.offset;
            self.offset += n;
            Some((start, n))
        } else if self.zlp {
            self.zlp = false;
            Some((self.offset, 0))
        } else {
            None
        }
    }
}
impl Default for ControlIn {
    fn default() -> Self {
        Self::new()
    }
}
