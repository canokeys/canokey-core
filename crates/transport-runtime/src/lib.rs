// SPDX-License-Identifier: Apache-2.0
//! Transport mechanisms shared by product-owned workspaces and IRQ facades.
#![no_std]
#![forbid(unsafe_code)]
pub mod nfc;
pub mod nfc_io;
pub mod nfc_provision;
