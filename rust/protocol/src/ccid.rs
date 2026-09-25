// SPDX-License-Identifier: Apache-2.0
//! CCID wire constants and byte encoding, independent of USB/native layout.
pub const HEADER: usize = 10;
pub const POWER_ON: u8 = 0x62;
pub const POWER_OFF: u8 = 0x63;
pub const SLOT_STATUS: u8 = 0x65;
pub const TRANSFER: u8 = 0x6f;
pub const GET_PARAMETERS: u8 = 0x6c;
pub const RESET_PARAMETERS: u8 = 0x6d;
pub const SET_PARAMETERS: u8 = 0x61;
pub const DATA: u8 = 0x80;
pub const STATUS: u8 = 0x81;
pub const PARAMETERS: u8 = 0x82;
pub const BAD_SLOT: u8 = 5;
pub const BAD_POWER: u8 = 7;
pub const BAD_LENGTH: u8 = 8;
pub const MUTE: u8 = 0xfe;
pub const HARDWARE: u8 = 0xfb;
pub const ATR: &[u8] = &[
    0x3b, 0xf7, 0x11, 0, 0, 0x81, 0x31, 0xfe, 0x65, 0x43, 0x61, 0x6e, 0x6f, 0x4b, 0x65, 0x79, 0x99,
];
pub const T1: &[u8] = &[0x11, 0x10, 0, 0x15, 0, 0xfe, 0];

pub fn payload_length(header: &[u8; HEADER]) -> u32 {
    u32::from_le_bytes(header[1..5].try_into().unwrap())
}

pub fn response(
    out: &mut [u8; HEADER],
    kind: u8,
    length: u32,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    specific: u8,
) {
    *out = [kind, 0, 0, 0, 0, slot, sequence, status, error, specific];
    out[1..5].copy_from_slice(&length.to_le_bytes());
}

pub fn extension(slot: u8, sequence: u8) -> [u8; HEADER] {
    [DATA, 0, 0, 0, 0, slot, sequence, 0x80, 1, 0]
}
