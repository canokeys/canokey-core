// SPDX-License-Identifier: Apache-2.0
//! Platform-independent protocol primitives. No applets, storage, allocator or FFI.
#![no_std]
// The only exception is utf8::str, which borrows bytes it has fully validated.
#![deny(unsafe_code)]

pub mod apdu;
pub mod cbor;
pub mod ctaphid;
pub mod response;
pub mod tlv;
pub mod utf8;

pub mod der;

pub mod ccid;
pub mod nfc;
pub mod usb;
