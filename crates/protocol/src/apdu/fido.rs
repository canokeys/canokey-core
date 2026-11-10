// SPDX-License-Identifier: Apache-2.0
//! FIDO proprietary APDU admission after applet and CLA routing.
use super::{FIDO_CBOR_INS, Header};
use crate::response::StatusWord;

/// CTAP NFC P1 bit 7 permits asynchronous response polling. A synchronous
/// implementation may complete directly; every other P1 bit and P2 is reserved.
pub const KEEPALIVE_HINT: u8 = 0x80;

#[inline]
pub fn valid_message_parameters(header: Header) -> bool {
    header.p1 & !KEEPALIVE_HINT == 0x00 && header.p2 == 0x00
}

/// CanoKey acknowledges unknown proprietary INS on intermediate fragments.
/// MSG parameters are checked when its semantic consumer begins; continuing
/// fragments share that consumer only when their complete headers match.
#[inline]
pub fn begin_message(header: Header) -> Result<(), StatusWord> {
    if header.ins != FIDO_CBOR_INS {
        if header.chained() {
            return Ok(());
        }
        return Err(StatusWord::INS_NOT_SUPPORTED);
    }
    if !valid_message_parameters(header) {
        return Err(StatusWord::WRONG_P1P2);
    }
    Ok(())
}

/// INS dispatch occurs after the last fragment. The caller then requires a
/// CTAP command byte from the complete logical request, even if this final
/// fragment has no body. U2F CLA 0x00 is a separate product capability.
#[inline]
pub fn finish_message(header: Header) -> Result<(), StatusWord> {
    if header.ins != FIDO_CBOR_INS {
        return Err(StatusWord::INS_NOT_SUPPORTED);
    }
    Ok(())
}
