// SPDX-License-Identifier: Apache-2.0
//! ADMIN's PASS configuration format. Common APDU types/status words are shared;
//! this format is not BER-TLV and has no applet-local APDU request structure.
#![forbid(unsafe_code)]
use crate::{
    codec::Layout,
    domain::{Error, KEY_LENGTH, PASSWORD_LIMIT, Slot, SlotIndex},
};
use canokey_protocol::response::StatusWord;

pub fn decode_config(p1: u8, data: &[u8]) -> Result<(SlotIndex, Slot<'_>), StatusWord> {
    let index = p1
        .checked_sub(1)
        .and_then(|v| SlotIndex::new(v).ok())
        .ok_or(StatusWord::WRONG_P1P2)?;
    let kind = *data.first().ok_or(StatusWord::WRONG_LENGTH)?;
    let slot = match kind {
        0 if data.len() == 1 => Slot::Off,
        2 if data.len() >= 3
            && usize::from(data[1]) <= PASSWORD_LIMIT
            && data.len() == 3 + usize::from(data[1]) =>
        {
            Slot::Static {
                password: &data[2..data.len() - 1],
                enter: data[data.len() - 1],
            }
        }
        3 if data.len() == 2 + KEY_LENGTH && usize::from(data[1]) == KEY_LENGTH => {
            Slot::Hmac(data[2..].try_into().map_err(|_| StatusWord::WRONG_LENGTH)?)
        }
        0 | 2 | 3 => return Err(StatusWord::WRONG_LENGTH),
        _ => return Err(StatusWord::WRONG_DATA),
    };
    Ok((index, slot))
}

fn description(slot: Slot<'_>) -> (u8, usize) {
    match slot {
        Slot::Off => (0, 1),
        Slot::Hmac(_) => (3, 1),
        Slot::Static { .. } => (2, 2),
        Slot::Oath { name, .. } => (1, name.len() + 3),
        Slot::Unknown(value) => (value as u8, 0),
    }
}

/// Exact writable capacity, including the historical unknown-type byte write.
pub fn read_capacity(bytes: &[u8], layout: Layout) -> Result<usize, Error> {
    let mut pos = 0;
    let mut capacity = 0;
    for i in 0..2 {
        let slot = layout.decode(layout.record(bytes, SlotIndex::new(i)?)?)?;
        let (_, n) = description(slot);
        capacity = capacity.max(pos + n.max(1));
        pos += n;
    }
    Ok(capacity)
}

/// Discovery never includes a static password or HMAC key.
pub fn read_config(bytes: &[u8], layout: Layout, output: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0;
    for i in 0..2 {
        let slot = layout.decode(layout.record(bytes, SlotIndex::new(i)?)?)?;
        let (kind, length) = description(slot);
        let end = pos + length;
        if output.len() < end.max(pos + 1) {
            return Err(Error::Output);
        }
        output[pos] = kind;
        match slot {
            Slot::Static { enter, .. } => output[pos + 1] = enter,
            Slot::Oath { name, enter, .. } => {
                output[pos + 1] = name.len() as u8;
                output[pos + 2..end - 1].copy_from_slice(name);
                output[end - 1] = enter;
            }
            _ => (),
        }
        pos = end; // Preserve C's unknown-type discovery behavior.
    }
    Ok(pos)
}

/// Generate discovery directly from stable slots; return the total length.
/// No password/key bytes are exposed and no full response buffer is retained.
pub fn read_config_part(
    bytes: &[u8],
    layout: Layout,
    offset: usize,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut position = 0;
    let mut emit = |byte| {
        if position >= offset {
            if let Some(target) = output.get_mut(position - offset) {
                *target = byte;
            }
        }
        position += 1;
    };
    for index in 0..2 {
        match layout.decode(layout.record(bytes, SlotIndex::new(index)?)?)? {
            Slot::Off => emit(0),
            Slot::Static { enter, .. } => {
                emit(2);
                emit(enter);
            }
            Slot::Hmac(_) => emit(3),
            Slot::Oath { name, enter, .. } => {
                emit(1);
                emit(name.len() as u8);
                for byte in name {
                    emit(*byte);
                }
                emit(enter);
            }
            Slot::Unknown(_) => return Err(Error::Record),
        }
    }
    if offset
        .checked_add(output.len())
        .is_none_or(|end| end > position)
    {
        return Err(Error::Output);
    }
    Ok(position)
}
