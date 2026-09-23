// SPDX-License-Identifier: Apache-2.0
//! OATH applet APDU assignments: INS is the instruction byte, and tag identifies
//! a one-byte-tag TLV (tag/length/value) field. HOTP uses an event counter;
//! TOTP uses a time-step challenge. These are wire values, not storage offsets.
pub(super) mod ins {
    pub const INS_PUT: u8 = 0x01;
    pub const INS_DELETE: u8 = 0x02;
    pub const INS_SET_CODE: u8 = 0x03;
    pub const INS_RENAME: u8 = 0x05;
    pub const INS_LIST: u8 = 0xa1;
    pub const INS_CALCULATE: u8 = 0xa2;
    pub const INS_VALIDATE: u8 = 0xa3;
    pub const INS_CALCULATE_ALL: u8 = 0xa4;
    pub const INS_SEND_REMAINING: u8 = 0xa5;
    pub const INS_SET_DEFAULT: u8 = 0x55;
}
pub(super) mod tag {
    pub const NAME: u8 = 0x71;
    pub const NAME_LIST: u8 = 0x72;
    pub const KEY: u8 = 0x73;
    pub const CHALLENGE: u8 = 0x74;
    pub const RESPONSE: u8 = 0x75;
    pub const TRUNCATED_RESPONSE: u8 = 0x76;
    pub const NO_RESPONSE: u8 = 0x77;
    pub const PROPERTY: u8 = 0x78;
    pub const VERSION: u8 = 0x79;
    pub const INITIAL_COUNTER: u8 = 0x7a;
    pub const ALGORITHM: u8 = 0x7b;
    pub const TOUCH_REQUIRED: u8 = 0x7c;
}

// Legacy YubiKey OTP commands share INS 01 with OATH PUT; P1 distinguishes
// these unauthenticated PASS operations from ordinary OATH credential writes.
pub(super) mod otp_selector {
    pub const SERIAL: u8 = 0x10;
    pub const CHALLENGE_SLOT_1: u8 = 0x30;
    pub const CHALLENGE_SLOT_2: u8 = 0x38;
}
