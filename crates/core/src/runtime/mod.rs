// SPDX-License-Identifier: Apache-2.0
pub mod engine;
#[cfg(has_applet)]
pub(crate) mod presence;
pub mod registry;

#[cfg(any(crypto_applet, feature = "admin"))]
pub(crate) mod workspace;

#[cfg(feature = "ctap")]
pub mod ctaphid;

#[cfg(feature = "ctap")]
pub use presence::Polling;

pub mod ccid;

pub mod config;
pub mod keyboard;
pub mod nfc;
pub mod nfc_io;
pub mod nfc_provision;
pub mod usb;
pub mod webusb;
