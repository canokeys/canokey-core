// SPDX-License-Identifier: Apache-2.0
//! Compact credential encoding: six header bytes, name, key and counter.
//! Storage identity belongs to the repository, not this codec.
use super::{
    Algorithm, Error,
    credential::{Credential, Kind, Properties},
};
pub const LENGTH: usize = 142;
pub fn length(header: &[u8]) -> Result<usize, Error> {
    if header.len() < 6
        || header[0] != 1
        || !(1..=64).contains(&header[1])
        || !(1..=64).contains(&header[2])
    {
        return Err(Error::Invalid);
    }
    Ok(14 + header[1] as usize + header[2] as usize)
}
pub fn encode(record: &Credential, out: &mut [u8; LENGTH]) -> usize {
    out[..6].copy_from_slice(&[
        1,
        record.name_len,
        record.key_len,
        record.kind as u8 | record.algorithm as u8,
        record.digits,
        record.properties.bits(),
    ]);
    let key_at = 6 + record.name().len();
    let counter_at = key_at + record.key().len();
    out[6..key_at].copy_from_slice(record.name());
    out[key_at..counter_at].copy_from_slice(record.key());
    out[counter_at..counter_at + 8].copy_from_slice(&record.moving_factor);
    counter_at + 8
}
pub fn decode(bytes: &[u8]) -> Result<Credential, Error> {
    if bytes.len() != length(bytes)? {
        return Err(Error::Invalid);
    }
    let kind = match bytes[3] & 0xf0 {
        0x10 => Kind::Hotp,
        0x20 => Kind::Totp,
        _ => return Err(Error::Invalid),
    };
    let key_at = 6 + bytes[1] as usize;
    let counter_at = key_at + bytes[2] as usize;
    Credential::new(
        &bytes[6..key_at],
        &bytes[key_at..counter_at],
        kind,
        Algorithm::from_byte(bytes[3] & 15)?,
        bytes[4],
        Properties::new(bytes[5])?,
        bytes[counter_at..].try_into().map_err(|_| Error::Invalid)?,
    )
}
