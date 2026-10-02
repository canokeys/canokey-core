// SPDX-License-Identifier: Apache-2.0
//! CCID wire constants and byte encoding, independent of USB/native layout.
pub const HEADER: usize = 10;
pub const SLOT_OFFSET: usize = 5;
pub const SEQUENCE_OFFSET: usize = 6;
pub const SPECIFIC_OFFSET: usize = 7;
pub const COMMAND_FAILED: u8 = 0x40;
pub const TIME_EXTENSION: u8 = 0x80;
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
pub const BAD_SLOT: u8 = 0x05;
pub const BAD_POWER: u8 = 0x07;
pub const BAD_LENGTH: u8 = 0x08;
pub const MUTE: u8 = 0xfe; // USB CCID 1.1 bError: ICC_MUTE (ICC did not respond).
pub const HARDWARE: u8 = 0xfb; // USB CCID 1.1 bError: HW_ERROR (hardware failure).
// ISO 7816-3 ATR: direct convention; seven historical bytes "CanoKey".
// TA1=Fi372/Di1; TD1/TD2 select T=1; TA3=IFSC254, TB3=BWI6/CWI5;
// TB1/TC1 are zero, and final 0x99 is the XOR check byte TCK.
pub const ATR: &[u8] = &[
    0x3b, 0xf7, 0x11, 0, 0, 0x81, 0x31, 0xfe, 0x65, 0x43, 0x61, 0x6e, 0x6f, 0x4b, 0x65, 0x79, 0x99,
];
// CCID 1.1 section 6.1.8: Fi/Di, TCCKS(T=1 direct), guard, BWI1/CWI5,
// clock stop, IFSC254, NAD0. These are CCID parameters, not the ATR TB3 value.
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
    // RDR_to_PC_DataBlock time extension, bError=1 requests one more BWT.
    [DATA, 0, 0, 0, 0, slot, sequence, TIME_EXTENSION, 1, 0]
}
