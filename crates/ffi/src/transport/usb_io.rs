// SPDX-License-Identifier: Apache-2.0
//! Select the Rust USB controller or an external controller supplied by a host.
#[cfg(feature = "usb-device")]
pub(crate) use super::usb::{ck_usb_configured, ck_usb_receive, ck_usb_submit, ck_usb_tx_idle};

#[cfg(all(test, feature = "usb-hid", not(feature = "usb-device")))]
pub(crate) use super::hid::link::tests::{
    ck_usb_configured, ck_usb_receive, ck_usb_submit, ck_usb_tx_idle,
};

#[cfg(not(any(feature = "usb-device", all(test, feature = "usb-hid"))))]
#[cfg_attr(test, allow(dead_code))]
unsafe extern "C" {
    pub(crate) fn ck_usb_configured() -> u8;
    pub(crate) fn ck_usb_tx_idle(endpoint: u8) -> u8;
    pub(crate) fn ck_usb_submit(endpoint: u8, bytes: *const u8, length: u16, zlp: u8) -> i32;
    pub(crate) fn ck_usb_receive(endpoint: u8);
}
