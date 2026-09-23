// SPDX-License-Identifier: Apache-2.0
//! Safe independent core; all C ABI and raw pointer access lives in ffi.
#![no_std]
#![forbid(unsafe_code)]
pub mod applets;
pub mod ports;
pub mod runtime;
pub use ports::Platform;
pub use runtime::engine::{Core, Reply};

#[cfg(any(feature = "admin", feature = "pass"))]
mod flows;

#[cfg(any(feature = "admin", feature = "openpgp", feature = "piv"))]
mod mechanisms;
