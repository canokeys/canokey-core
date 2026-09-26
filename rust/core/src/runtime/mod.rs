// SPDX-License-Identifier: Apache-2.0
pub mod engine;
#[cfg(has_applet)]
pub(crate) mod presence;
pub mod registry;

#[cfg(crypto_applet)]
pub(crate) mod workspace;

#[cfg(feature = "ctap")]
pub mod ctaphid;

#[cfg(feature = "ctap")]
pub use presence::Polling;

pub mod ccid;

pub mod keyboard;
pub mod usb;
