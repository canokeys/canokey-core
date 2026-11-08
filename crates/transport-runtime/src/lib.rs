// SPDX-License-Identifier: Apache-2.0
//! Transport mechanisms shared by product-owned workspaces and IRQ facades.
#![no_std]
#![forbid(unsafe_code)]
pub mod ccid;
pub mod ctaphid;
pub mod nfc;
pub mod nfc_io;
pub mod nfc_provision;
pub mod usb;

pub mod engine;

pub mod frame;
