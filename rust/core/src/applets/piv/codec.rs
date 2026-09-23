// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::{
        length::{Feed, LengthState},
        write_length,
    },
};
pub fn take<'a>(bytes: &mut &'a [u8]) -> Result<(u8, &'a [u8]), Sw> {
    let tag = *bytes.first().ok_or(Sw::WRONG_LENGTH)?;
    let mut n = 1;
    let mut length = LengthState::Initial;
    let size = loop {
        let b = *bytes.get(n).ok_or(Sw::WRONG_LENGTH)?;
        n += 1;
        match length.feed(b) {
            Feed::More => (),
            Feed::Invalid => return Err(Sw::WRONG_DATA),
            Feed::Complete(l) => break l as usize,
        }
    };
    let value = bytes.get(n..n + size).ok_or(Sw::WRONG_LENGTH)?;
    *bytes = &bytes[n + size..];
    Ok((tag, value))
}
pub fn object(bytes: &[u8], tag: u8) -> Result<&[u8], Sw> {
    let mut rest = bytes;
    let (t, v) = take(&mut rest)?;
    if t != tag || !rest.is_empty() {
        return Err(Sw::WRONG_DATA);
    }
    Ok(v)
}
pub fn header(out: &mut [u8], tag: &[u8], n: usize) -> Result<usize, Sw> {
    if n > 65535 || out.len() < tag.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    out[..tag.len()].copy_from_slice(tag);
    Ok(tag.len() + write_length(n as u16, &mut out[tag.len()..]).map_err(|_| Sw::WRONG_LENGTH)?)
}
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    a.iter()
        .zip(b)
        .fold(a.len() ^ b.len(), |v, (a, b)| v | usize::from(a ^ b))
        == 0
}
pub fn tag_list(b: &[u8]) -> Result<(u32, usize), Sw> {
    if b.len() < 2 {
        return Err(Sw::WRONG_LENGTH);
    }
    if b[0] != 0x5c {
        return Err(Sw::WRONG_DATA);
    }
    let n = b[1] as usize;
    if !(1..=3).contains(&n) || b.len() < 2 + n {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok((
        b[2..2 + n].iter().fold(0, |v, b| (v << 8) | u32::from(*b)),
        2 + n,
    ))
}

pub(super) fn der_signature(out: &mut [u8], n: usize) -> Result<usize, Sw> {
    if !n.is_multiple_of(2) || n > 132 {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    let width = n / 2;
    let mut der = [0; 144];
    let mut at = 3;
    for value in out[..n].chunks_exact(width) {
        let skip = value
            .iter()
            .position(|v| *v != 0)
            .unwrap_or(value.len() - 1);
        let v = &value[skip..];
        let pad = usize::from(v[0] & 0x80 != 0);
        der[at] = 2;
        der[at + 1] = (v.len() + pad) as u8;
        at += 2;
        der[at..at + pad].fill(0);
        at += pad;
        der[at..at + v.len()].copy_from_slice(v);
        at += v.len();
    }
    let body = at - 3;
    let start = if body < 128 {
        der[1] = 0x30;
        der[2] = body as u8;
        1
    } else {
        der[0] = 0x30;
        der[1] = 0x81;
        der[2] = body as u8;
        0
    };
    out[..at - start].copy_from_slice(&der[start..at]);
    Ok(at - start)
}
