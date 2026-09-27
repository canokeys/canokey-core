// SPDX-License-Identifier: Apache-2.0
//! ADMIN's PASS configuration format. Common APDU types/status words are shared;
//! this format is not BER-TLV and has no applet-local APDU request structure.
#![forbid(unsafe_code)]
use crate::applets::pass::{
    codec::Layout,
    domain::{Error, KEY_LENGTH, PASSWORD_LIMIT, Slot, SlotIndex, kind},
};
use canokey_protocol::response::StatusWord;

// Two slots; worst case per slot is kind + name length + 64-byte name + Enter.
pub const MAX_DESCRIPTION_LENGTH: usize = 2 * (1 + 1 + 64 + 1);

// ADMIN uses one-based P1 slots (1/2); the domain uses zero-based indexes.
// Payloads: OFF=[kind], STATIC=[kind,len,password...,enter], HMAC=[kind,len,key...].
// OATH bindings are established through the OATH applet, not this decoder.
pub fn decode_config(p1: u8, data: &[u8]) -> Result<(SlotIndex, Slot<'_>), StatusWord> {
    let index = p1
        .checked_sub(1)
        .and_then(|v| SlotIndex::new(v).ok())
        .ok_or(StatusWord::WRONG_P1P2)?;
    let kind = *data.first().ok_or(StatusWord::WRONG_LENGTH)?;
    let slot = match kind {
        kind::OFF if data.len() == 1 => Slot::Off,
        kind::STATIC
            if data.len() >= 3
                && usize::from(data[1]) <= PASSWORD_LIMIT
                && data.len() == 3 + usize::from(data[1]) =>
        {
            Slot::Static {
                password: &data[2..data.len() - 1],
                enter: data[data.len() - 1],
            }
        }
        kind::HMAC if data.len() == 2 + KEY_LENGTH && usize::from(data[1]) == KEY_LENGTH => {
            Slot::Hmac(data[2..].try_into().map_err(|_| StatusWord::WRONG_LENGTH)?)
        }
        kind::OFF | kind::STATIC | kind::HMAC => return Err(StatusWord::WRONG_LENGTH),
        _ => return Err(StatusWord::WRONG_DATA),
    };
    Ok((index, slot))
}
/// Generate discovery directly from stable slots; return the total length.
/// No password/key bytes are exposed and no full response buffer is retained.
pub fn read_config(bytes: &[u8], layout: Layout, output: &mut [u8]) -> Result<usize, Error> {
    let mut position = 0;
    let mut emit = |byte| {
        if let Some(target) = output.get_mut(position) {
            *target = byte;
        }
        position += 1;
    };
    for index in 0..crate::applets::pass::codec::SLOT_COUNT {
        match layout.decode(layout.record(bytes, SlotIndex::new(index as u8)?)?)? {
            Slot::Off => emit(kind::OFF),
            Slot::Oath { name, enter, .. } => {
                emit(kind::OATH);
                emit(name.len() as u8);
                for byte in name {
                    emit(*byte);
                }
                emit(enter);
            }
            Slot::Static { enter, .. } => {
                emit(kind::STATIC);
                emit(enter);
            }
            Slot::Hmac(_) => emit(kind::HMAC),
        }
    }
    if position > output.len() {
        return Err(Error::Output);
    }
    Ok(position)
}
