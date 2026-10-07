// SPDX-License-Identifier: Apache-2.0
//! Legacy YubiKey OTP route, outside the OATH access-code gate.
use super::wire::{ins::INS_PUT, otp_selector};
use crate::{
    Platform,
    applets::pass::{
        domain::{CHALLENGE_LIMIT, KEY_LENGTH, Slot},
        service::Pass,
    },
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

pub(super) fn matches(h: Header) -> bool {
    h.ins == INS_PUT
        && matches!(
            h.p1,
            otp_selector::SERIAL | otp_selector::CHALLENGE_SLOT_1 | otp_selector::CHALLENGE_SLOT_2
        )
}

pub(super) fn execute(
    h: Header,
    data: &[u8],
    pass: Option<&mut Pass>,
    p: &mut Platform<'_>,
    output: &mut [u8],
) -> Result<usize, Sw> {
    if h.p2 != 0x00 {
        return Err(Sw::WRONG_P1P2);
    }
    if h.p1 == otp_selector::SERIAL {
        if !data.is_empty() {
            return Err(Sw::WRONG_LENGTH);
        }
        let mut serial = [0; 4];
        p.device.serial(&mut serial);
        return Ok(crate::applets::write_serial(output, |out| *out = serial));
    }
    if data.len() > CHALLENGE_LIMIT {
        return Err(Sw::WRONG_LENGTH);
    }
    let index = u8::from(h.p1 == otp_selector::CHALLENGE_SLOT_2);
    let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
    if !matches!(pass.slot(index), Ok(Slot::Hmac(_))) {
        return Err(Sw::FILE_NOT_FOUND);
    }
    let mut result = [0; KEY_LENGTH];
    pass.challenge(index, data, &mut result, p)
        .map_err(crate::applets::pass::status)?;
    output[..KEY_LENGTH].copy_from_slice(&result);
    p.memory.wipe(&mut result);
    Ok(KEY_LENGTH)
}
