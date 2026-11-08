// SPDX-License-Identifier: Apache-2.0
//! CanoKey USB composition and discovery policy for the shared control runtime.
#![forbid(unsafe_code)]
pub mod bos;
pub mod descriptors;
use canokey_protocol::usb::*;
pub use canokey_transport_runtime::usb::ControlIn;
use canokey_transport_runtime::usb::{Configuration as ControlConfiguration, Hid, Profile};
use descriptors::Configuration;
pub type Reply = canokey_transport_runtime::usb::Reply<bos::Descriptor>;
pub type Device = canokey_transport_runtime::usb::Device<CanoKey, CONTROL_BUFFER_BYTES>;

pub struct CanoKey {
    idle: [u8; 2],
    pub leds: u8,
    pub landing: bool,
}
impl Profile<CONTROL_BUFFER_BYTES> for CanoKey {
    type Configuration = Configuration;
    type Descriptor = bos::Descriptor;
    const INITIAL: Self = Self {
        idle: [0x00; 2],
        leds: 0x00,
        landing: true,
    };
    const DEVICE: &'static [u8] = descriptors::DEVICE;
    const ACK_CURRENT_CONFIGURATION: bool = true;
    fn reset(&mut self) {
        let landing = self.landing;
        *self = Self::INITIAL;
        self.landing = landing;
    }
    fn string(index: u8, configuration: &Configuration) -> Option<&'static [u8]> {
        match index {
            STRING_MANUFACTURER => Some(b"canokeys.org"),
            STRING_PRODUCT => Some(b"CanoKey Rust Core"),
            STRING_WEBUSB if configuration.interfaces().webusb => Some(b"WebUSB"),
            _ => None,
        }
    }
    fn idle(&mut self, slot: usize) -> &mut u8 {
        &mut self.idle[slot]
    }
    fn discovery(&self, configuration: &Configuration, setup: Setup) -> Option<bos::Descriptor> {
        let interfaces = configuration.interfaces();
        if !interfaces.webusb {
            return None;
        }
        bos::Descriptor::request(setup, interfaces.webusb()).map(|descriptor| {
            if descriptor == bos::Descriptor::Bos && !self.landing {
                bos::Descriptor::BosWithoutLanding
            } else {
                descriptor
            }
        })
    }
}
impl ControlConfiguration<CONTROL_BUFFER_BYTES> for Configuration {
    fn count(&self) -> u8 {
        self.interfaces().count()
    }
    fn endpoint(&self, address: u16) -> bool {
        self.interfaces().endpoint(address)
    }
    fn copy_into(&self, out: &mut [u8; CONTROL_BUFFER_BYTES]) -> usize {
        self.copy_into(out)
    }
    fn usb_210(&self) -> bool {
        self.interfaces().webusb
    }
    fn hid(&self, interface: u16) -> Option<Hid> {
        self.interfaces().hid_interface(interface).map(|slot| Hid {
            idle_slot: slot,
            last_report_id: if slot == 1 { CONSUMER_REPORT_ID } else { 0x00 },
            descriptor: if slot == 1 {
                descriptors::KEYBOARD_HID
            } else {
                descriptors::CTAP_HID
            },
            report: if slot == 1 {
                descriptors::KEYBOARD_REPORT
            } else {
                descriptors::CTAP_REPORT
            },
            keyboard_leds: slot == 1,
        })
    }
}
