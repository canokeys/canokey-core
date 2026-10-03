// SPDX-License-Identifier: Apache-2.0
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
pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
    unsafe extern "C" {
        fn ck_usb_dcd_lock() -> u32;
        fn ck_usb_dcd_unlock(mask: u32);
    }
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}

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
