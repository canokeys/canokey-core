// SPDX-License-Identifier: Apache-2.0
//! Product-independent CTAP contracts; applications own storage and backing.
#![no_std]
#![forbid(unsafe_code)]

pub mod authorization;
pub mod client_pin;
pub mod config;
pub mod credential;
pub mod ports;
pub mod presence;
pub mod provision;
pub mod registration;
pub mod request;
pub mod resident;
pub mod response;
pub mod selection;
pub mod session;
pub mod settings;
pub mod signing;
pub mod status;
#[cfg(feature = "streaming")]
pub mod streaming;
pub mod workspace;

pub mod info;
#[cfg(feature = "schema")]
extern crate std;
#[cfg(feature = "schema")]
pub mod schema;
