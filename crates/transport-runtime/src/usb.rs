// SPDX-License-Identifier: Apache-2.0
//! USB control policy. IRQ-local USB state never borrows applet or session state.
#![forbid(unsafe_code)]
use canokey_protocol::usb::*;
pub mod descriptors;
mod lifecycle;
pub use lifecycle::Lifecycle;

// USB 2.0 chapter 9 and HID 1.11 descriptor types and fixed request fields.
const DESCRIPTOR_DEVICE: u8 = 0x01;
const DESCRIPTOR_CONFIGURATION: u8 = 0x02;
const DESCRIPTOR_STRING: u8 = 0x03;
const DESCRIPTOR_HID: u8 = 0x21;
const DESCRIPTOR_HID_REPORT: u8 = 0x22;
const LANGUAGE_EN_US: u16 = 0x0409;
const MAX_DEVICE_ADDRESS: u16 = 0x007f;
const KEYBOARD_LED_REPORT: u16 = 0x0201;
const KEYBOARD_LED_BYTES: u16 = 2;
pub const LANGUAGE: &[u8] = &[0x04, DESCRIPTOR_STRING, 0x09, 0x04];

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
// HID 1.11: one subordinate report descriptor; CTAP has no country or report ID.
pub const CTAP_HID: &[u8] = &[
    0x09,
    DESCRIPTOR_HID,
    0x11,
    0x01,
    0x00,
    0x01,
    DESCRIPTOR_HID_REPORT,
    CTAP_REPORT.len() as u8,
    0x00,
];

/// One advertised HID interface. Idle slots and report IDs are distinct:
/// CTAP uses slot 0 and unnumbered reports; a keyboard may use report IDs 1/2.
pub struct Hid {
    pub idle_slot: usize,
    pub last_report_id: u8,
    pub descriptor: &'static [u8],
    pub report: &'static [u8],
    pub keyboard_leds: bool,
}
/// Immutable product composition, built once outside IRQ request processing.
pub trait Configuration<const BUFFER: usize> {
    fn count(&self) -> u8;
    fn endpoint(&self, address: u16) -> bool;
    fn hid(&self, interface: u16) -> Option<Hid>;
    fn copy_into(&self, out: &mut [u8; BUFFER]) -> usize;
    fn usb_210(&self) -> bool {
        false
    }
}
/// Static USB product policy. No application, session, transport workspace or
/// hardware references enter this capability. Discovery may return an opaque
/// descriptor handle; the outer facade remains responsible for streaming it.
pub trait Profile<const BUFFER: usize>: Sized {
    type Configuration: Configuration<BUFFER>;
    type Descriptor;
    const INITIAL: Self;
    const DEVICE: &'static [u8];
    fn reset(&mut self);
    fn string(index: u8, configuration: &Self::Configuration) -> Option<&'static [u8]>;
    fn idle(&mut self, slot: usize) -> &mut u8;
    fn discovery(
        &self,
        _configuration: &Self::Configuration,
        _setup: Setup,
    ) -> Option<Self::Descriptor> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply<D> {
    Data(usize),
    Descriptor(D),
    Status,
    Address(u8),
    Configure(bool),
    Interface(u8),
    Halt(u8, bool),
    ReceiveLed,
    Stall,
}
pub struct Device<P: Profile<BUFFER>, const BUFFER: usize> {
    pub address: u8,
    pub configured: bool,
    pub policy: P,
}
impl<P: Profile<BUFFER>, const BUFFER: usize> Device<P, BUFFER> {
    pub const fn new() -> Self {
        Self {
            address: 0x00,
            configured: false,
            policy: P::INITIAL,
        }
    }
    pub fn reset(&mut self) {
        self.address = 0x00;
        self.configured = false;
        self.policy.reset();
    }
    pub fn setup(
        &mut self,
        configuration: &P::Configuration,
        s: Setup,
        stalled: bool,
        out: &mut [u8; BUFFER],
    ) -> Reply<P::Descriptor> {
        if let Some(descriptor) = self.policy.discovery(configuration, s) {
            return Reply::Descriptor(descriptor);
        }
        let zero_value_and_index = s.value == 0x0000 && s.index == 0x0000;
        match (s.kind, s.request) {
            (DEVICE_IN, GET_DESCRIPTOR) if s.value as u8 == 0x00 && s.index == 0x0000 => {
                let desc = match (s.value >> 8) as u8 {
                    DESCRIPTOR_DEVICE => P::DEVICE,
                    DESCRIPTOR_CONFIGURATION => return Reply::Data(configuration.copy_into(out)),
                    DESCRIPTOR_STRING => LANGUAGE,
                    _ => return Reply::Stall,
                };
                out[..desc.len()].copy_from_slice(desc);
                if s.value >> 8 == u16::from(DESCRIPTOR_DEVICE) && configuration.usb_210() {
                    // WebUSB BOS platform capabilities require bcdUSB 2.10.
                    out[2] = 0x10;
                }
                Reply::Data(desc.len())
            }
            (DEVICE_IN, GET_DESCRIPTOR)
                if s.value >> 8 == u16::from(DESCRIPTOR_STRING)
                    && (s.index == 0x0000 || s.index == LANGUAGE_EN_US) =>
            {
                let Some(text) = P::string(s.value as u8, configuration) else {
                    return Reply::Stall;
                };
                Reply::Data(string(text, out))
            }
            (DEVICE_OUT, SET_ADDRESS)
                if s.index == 0x0000
                    && s.length == 0
                    && s.value <= MAX_DEVICE_ADDRESS
                    && !self.configured =>
            {
                Reply::Address(s.value as u8)
            }
            (DEVICE_OUT, SET_CONFIGURATION)
                if s.index == 0x0000
                    && s.length == 0
                    && s.value <= 0x0001
                    && self.address != 0x00 =>
            {
                let enabled = s.value != 0x0000;
                if self.configured == enabled {
                    // Repetition acknowledges the current configuration without
                    // resetting endpoint leases or application sessions.
                    Reply::Status
                } else {
                    Reply::Configure(enabled)
                }
            }
            (DEVICE_IN, GET_CONFIGURATION)
                if zero_value_and_index && s.length == 1 && self.address != 0x00 =>
            {
                out[0] = self.configured as u8;
                Reply::Data(1)
            }
            (DEVICE_IN, GET_STATUS) if zero_value_and_index && s.length == 2 => {
                out[..2].fill(0x00);
                Reply::Data(2)
            }
            (INTERFACE_IN, GET_STATUS)
                if self.configured
                    && s.index < configuration.count() as u16
                    && s.value == 0x0000
                    && s.length == 2 =>
            {
                out[..2].fill(0x00);
                Reply::Data(2)
            }
            (INTERFACE_IN, GET_INTERFACE)
                if self.configured
                    && s.index < configuration.count() as u16
                    && s.value == 0x0000
                    && s.length == 1 =>
            {
                out[0] = 0x00;
                Reply::Data(1)
            }
            (INTERFACE_OUT, SET_INTERFACE)
                if self.configured
                    && s.index < configuration.count() as u16
                    && s.value == 0x0000
                    && s.length == 0 =>
            {
                Reply::Interface(s.index as u8)
            }
            (ENDPOINT_IN, GET_STATUS)
                if s.value == 0x0000
                    && s.length == 2
                    && self.valid_endpoint(configuration, s.index) =>
            {
                out[0] = stalled as u8;
                out[1] = 0x00;
                Reply::Data(2)
            }
            (ENDPOINT_OUT, CLEAR_FEATURE | SET_FEATURE)
                if self.configured
                    && s.value == 0x0000
                    && s.length == 0
                    && self.valid_endpoint(configuration, s.index)
                    && s.index & u16::from(ENDPOINT_NUMBER_MASK) != 0x0000 =>
            {
                Reply::Halt(s.index as u8, s.request == SET_FEATURE)
            }
            _ => self.hid(configuration, s, out),
        }
    }
    fn valid_endpoint(&self, configuration: &P::Configuration, endpoint: u16) -> bool {
        configuration.endpoint(endpoint)
            && (endpoint & u16::from(ENDPOINT_NUMBER_MASK) == 0x0000 || self.configured)
    }
    fn hid(
        &mut self,
        configuration: &P::Configuration,
        s: Setup,
        out: &mut [u8; BUFFER],
    ) -> Reply<P::Descriptor> {
        if !self.configured {
            return Reply::Stall;
        }
        let Some(hid) = configuration.hid(s.index) else {
            return Reply::Stall;
        };
        match (s.kind, s.request) {
            (INTERFACE_IN, GET_DESCRIPTOR) if s.value as u8 == 0x00 => {
                let bytes = match (s.value >> 8) as u8 {
                    DESCRIPTOR_HID => hid.descriptor,
                    DESCRIPTOR_HID_REPORT => hid.report,
                    _ => return Reply::Stall,
                };
                out[..bytes.len()].copy_from_slice(bytes);
                Reply::Data(bytes.len())
            }
            (CLASS_INTERFACE_OUT, HID_SET_IDLE)
                if s.length == 0 && s.value as u8 <= hid.last_report_id =>
            {
                *self.policy.idle(hid.idle_slot) = (s.value >> 8) as u8;
                Reply::Status
            }
            (CLASS_INTERFACE_IN, HID_GET_IDLE)
                if s.length == 1 && s.value <= u16::from(hid.last_report_id) =>
            {
                out[0] = *self.policy.idle(hid.idle_slot);
                Reply::Data(1)
            }
            // Keyboard LEDs, report ID 1. HID protocol is report-only: the
            // interface does not advertise boot protocol or remote wakeup.
            (CLASS_INTERFACE_OUT, HID_SET_REPORT)
                if hid.keyboard_leds
                    && s.value == KEYBOARD_LED_REPORT
                    && s.length == KEYBOARD_LED_BYTES =>
            {
                Reply::ReceiveLed
            }
            _ => Reply::Stall,
        }
    }
}
impl<P: Profile<BUFFER>, const BUFFER: usize> Default for Device<P, BUFFER> {
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

pub fn string<const BUFFER: usize>(text: &[u8], out: &mut [u8; BUFFER]) -> usize {
    let n = text.len().min((BUFFER - 2) / 2);
    out[0] = (2 + 2 * n) as u8;
    out[1] = DESCRIPTOR_STRING;
    for (i, ch) in text[..n].iter().enumerate() {
        out[2 + 2 * i] = *ch;
        out[3 + 2 * i] = 0x00;
    }
    2 + 2 * n
}
