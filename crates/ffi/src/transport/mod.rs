// SPDX-License-Identifier: Apache-2.0
#[cfg(any(
    feature = "usb-ccid",
    feature = "usb-hid",
    feature = "usb-keyboard",
    feature = "device-runtime"
))]
mod lock;
#[cfg(any(feature = "usb-ccid", feature = "usb-webusb", feature = "nfc"))]
mod owners;
#[cfg(feature = "ctap")]
mod pke_scratch;
#[cfg(any(
    feature = "usb-ccid",
    feature = "usb-hid",
    feature = "usb-keyboard",
    feature = "device-runtime"
))]
pub(crate) use lock::usb_locked;

#[cfg(feature = "usb-ccid")]
pub(crate) mod ccid;
#[cfg(feature = "ctap")]
pub(crate) mod hid;
#[cfg(feature = "usb-keyboard")]
pub(crate) mod keyboard;
#[cfg(feature = "nfc")]
pub(crate) mod nfc;
#[cfg(feature = "usb-device")]
pub(crate) mod usb;
#[cfg(feature = "usb-webusb")]
pub(crate) mod webusb;
