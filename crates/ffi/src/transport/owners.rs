// SPDX-License-Identifier: Apache-2.0
// Session identities must match runtime/engine.rs, including extended admission.
#[cfg(feature = "usb-ccid")]
pub const OWNER_CCID: u8 = 1;
#[cfg(feature = "usb-webusb")]
pub const OWNER_WEBUSB: u8 = 3;
#[cfg(feature = "nfc")]
pub const OWNER_NFC: u8 = 4;
