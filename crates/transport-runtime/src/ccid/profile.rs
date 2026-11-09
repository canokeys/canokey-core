// SPDX-License-Identifier: Apache-2.0
//! Single-slot short-APDU card contract shared by both products.
use super::Policy;
use canokey_protocol::ccid::*;

/// CanoKey card identity, automatic voltage selection and read-only parameters.
/// ICC power commands reset the application owner. As in the CanoKey card, a
/// complete short APDU can activate an inactive logical slot; application
/// selection and authentication remain enforced by the serialized backend.
pub struct ShortApdu;
impl Policy for ShortApdu {
    const ATR: &'static [u8] = ATR;
    const PARAMETERS: &'static [u8] = T1;
    const SUCCESS_ERROR: u8 = SUCCESS_ERROR;
    const WRITE_PARAMETERS: bool = false;
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
