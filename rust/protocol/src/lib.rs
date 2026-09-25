// SPDX-License-Identifier: Apache-2.0
//! Platform-independent protocol primitives. No applets, storage, allocator or FFI.
#![no_std]
#![forbid(unsafe_code)]

pub mod apdu;
pub mod cbor;
pub mod ctaphid;
pub mod response;
pub mod tlv;

pub mod der;

pub mod ccid;
