// SPDX-License-Identifier: Apache-2.0
//! CanoKey short-only CCID validation and card identity.
use canokey_protocol::ccid::*;
pub use canokey_transport_runtime::ccid::Backend;
use canokey_transport_runtime::ccid::Policy;
pub const FRAME: usize = canokey_protocol::apdu::SHORT_FRAME_BYTES;
pub const REPLY: usize = canokey_protocol::apdu::SHORT_REPLY_BYTES;
pub const CONTROL_REPLY: usize = HEADER + ATR.len();
pub use canokey_transport_runtime::ccid::EXTENSION_INTERVAL;
pub type Transport =
    canokey_transport_runtime::ccid::Transport<CanoKey, canokey_transport_runtime::ccid::Buffered>;
pub struct CanoKey;
impl Policy for CanoKey {
    const ATR: &'static [u8] = ATR;
    const PARAMETERS: &'static [u8] = T1;
    const SUCCESS_ERROR: u8 = SUCCESS_ERROR;
    const WRITE_PARAMETERS: bool = false;
    fn header_error(header: &[u8; HEADER], length: u32, _active: bool) -> u8 {
        if header[0] == TRANSFER && length > FRAME as u32 {
            BAD_LENGTH
        } else {
            0x00
        }
    }
    fn validate(header: &[u8; HEADER], receive_error: u8) -> u8 {
        // Slot and control-envelope errors precede transport input rejection.
        let command = header[0];
        let reserved = match command {
            POWER_ON => 2,
            POWER_OFF | SLOT_STATUS | GET_PARAMETERS => 3,
            _ => 0,
        };
        if header[SLOT_OFFSET] != 0x00 {
            BAD_SLOT
        } else if reserved != 0 && payload_length(header) != 0 {
            BAD_LENGTH
        } else if reserved != 0
            && (header[8] != 0x00
                || header[9] != 0x00
                || (reserved == 3 && header[SPECIFIC_OFFSET] != 0x00))
        {
            if reserved == 2 { BAD_RFU2 } else { BAD_POWER }
        } else if receive_error != 0x00 {
            receive_error
        } else if command == POWER_ON && header[SPECIFIC_OFFSET] != 0x00 {
            BAD_POWER
        } else {
            0x00
        }
    }
}
