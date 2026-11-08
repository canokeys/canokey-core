// SPDX-License-Identifier: Apache-2.0
//! Product-independent CTAP contracts; applications own storage and backing.
#![no_std]
#![forbid(unsafe_code)]

pub mod config;
pub mod ports;
pub mod presence;
pub mod request;
pub mod status;

pub mod info;
#[cfg(feature = "schema")]
extern crate std;
#[cfg(feature = "schema")]
pub mod schema;
