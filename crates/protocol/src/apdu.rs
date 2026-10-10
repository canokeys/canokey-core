// SPDX-License-Identifier: Apache-2.0
mod chain;
mod decode;
mod header;
pub use chain::{ChainStep, CommandChain};
pub use decode::{FrameDecoder, FrameEvent, parse};
pub use header::*;
// FIDO Alliance AID: RID A000000647, PIX 2F0001 (FIDO/U2F applet).
pub const FIDO_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
// FIDO/U2F APDU dispatch assignments after explicit applet selection.
pub const CLA_CHAINING: u8 = 0x10;
pub const CLA_FIDO: u8 = 0x80;
pub const INS_SELECT: u8 = 0xa4;
pub const SELECT_BY_NAME: u8 = 0x04;
pub const FIDO_CBOR_INS: u8 = 0x10;
pub const U2F_REGISTER: u8 = 0x01;
pub const U2F_AUTHENTICATE: u8 = 0x02;
pub const U2F_VERSION: u8 = 0x03;
pub const STATUS_BYTES: usize = 2;
pub const SHORT_DATA_BYTES: usize = 256;
pub const SHORT_HEADER_BYTES: usize = 5;
pub const SHORT_REPLY_BYTES: usize = SHORT_DATA_BYTES + STATUS_BYTES;
pub const SHORT_FRAME_BYTES: usize = SHORT_HEADER_BYTES + SHORT_DATA_BYTES;
pub const EXTENDED_HEADER_BYTES: usize = 7; // CLA INS P1 P2, zero marker, Lc16.
pub const EXTENDED_LE_BYTES: usize = 2;
pub const EXTENDED_OVERHEAD_BYTES: usize = EXTENDED_HEADER_BYTES + EXTENDED_LE_BYTES;
pub const MAX_FRAME: usize = EXTENDED_OVERHEAD_BYTES + u16::MAX as usize;
pub const MORE_DATA_SW1: u8 = 0x61;
// Case-2 GET RESPONSE: CLA 00, INS C0, P1/P2 00, Le 00 (256 bytes).
pub const GET_RESPONSE: [u8; SHORT_HEADER_BYTES] = [0x00, 0xc0, 0x00, 0x00, 0x00];
pub const RESPONSE_CHAIN_LIMIT: usize = 256;
// Shared applet response-preemption policy; bounded short responses retain ownership.
pub const RESPONSE_PREEMPT_BYTES: usize = 288;
