// SPDX-License-Identifier: Apache-2.0
//! Safe independent core; all C ABI and raw pointer access lives in ffi.
#![no_std]
#![forbid(unsafe_code)]

#[allow(dead_code)] // Reduced applet/interface profiles consume only some fields.
pub(crate) mod release {
    include!(concat!(env!("OUT_DIR"), "/release_versions.rs"));
}
pub mod applets;
pub mod ports;
pub mod runtime;
pub use ports::Platform;
pub use runtime::engine::{Core, Reply};

#[cfg(any(feature = "admin", feature = "pass", feature = "oath"))]
mod flows;

#[cfg(any(
    feature = "admin",
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap"
))]
mod mechanisms;
