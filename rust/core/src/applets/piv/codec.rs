// SPDX-License-Identifier: Apache-2.0
use super::wire::object_tlv;
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::{
        length::{Feed, LengthState},
        write_length,
    },
};
/// Consume one single-byte-tag BER-TLV and advance the borrowed input slice.
/// Unlike object(), trailing sibling TLVs are allowed.
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
    if n > u16::MAX as usize || out.len() < tag.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    out[..tag.len()].copy_from_slice(tag);
    Ok(tag.len() + write_length(n as u16, &mut out[tag.len()..]).map_err(|_| Sw::WRONG_LENGTH)?)
}
// Fold every overlapping byte and the public length difference; do not
// return early at the first differing secret byte.
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
    if b[0] != object_tlv::TAG_LIST {
        return Err(Sw::WRONG_DATA);
    }
    let n = b[1] as usize;
    if !(1..=object_tlv::MAX_TAG_BYTES).contains(&n) || b.len() < 2 + n {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok((
        b[2..2 + n].iter().fold(0, |v, b| (v << 8) | u32::from(*b)),
        2 + n,
    ))
}

pub(super) use canokey_protocol::der::der_signature;
