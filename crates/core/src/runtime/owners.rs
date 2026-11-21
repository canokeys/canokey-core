// SPDX-License-Identifier: Apache-2.0
//! Transport session identities. PKE leases use a separate numbering space.

/// Zero stands for an absent transport owner.
pub const OWNER_INVALID: u8 = 0x00;
/// USB CCID APDUs.
pub const OWNER_CCID: u8 = 0x01;
/// Native CTAP over USB HID.
pub const OWNER_CTAP: u8 = 0x02;
/// WebUSB APDUs.
pub const OWNER_WEBUSB: u8 = 0x03;
/// Contactless APDUs.
pub const OWNER_NFC: u8 = 0x04;
