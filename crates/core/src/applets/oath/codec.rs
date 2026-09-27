// SPDX-License-Identifier: Apache-2.0
//! Compact credential encoding: six header bytes, name, key and counter.
//! Storage identity belongs to the repository, not this codec.
use super::{
    Algorithm, Error,
    credential::{Credential, Kind, Properties},
};
const FORMAT_VERSION: u8 = 1;
const VERSION: usize = 0;
const NAME_LENGTH: usize = 1;
const KEY_LENGTH: usize = 2;
const TYPE: usize = 3;
const DIGITS: usize = 4;
const PROPERTIES: usize = 5;
pub const HEADER_BYTES: usize = 6;
pub const COUNTER_BYTES: usize = 8;
pub const FIXED_BYTES: usize = HEADER_BYTES + COUNTER_BYTES;
pub use super::credential::{KEY_LIMIT, NAME_LIMIT};
pub const LENGTH: usize = FIXED_BYTES + NAME_LIMIT + KEY_LIMIT;
pub fn length(header: &[u8]) -> Result<usize, Error> {
    if header.len() < HEADER_BYTES
        || header[VERSION] != FORMAT_VERSION
        || !(1..=NAME_LIMIT as u8).contains(&header[NAME_LENGTH])
        || !(1..=KEY_LIMIT as u8).contains(&header[KEY_LENGTH])
    {
        return Err(Error::Invalid);
    }
    Ok(FIXED_BYTES + header[NAME_LENGTH] as usize + header[KEY_LENGTH] as usize)
}
pub fn encode(record: &Credential, out: &mut [u8; LENGTH]) -> usize {
    out[..HEADER_BYTES].copy_from_slice(&[
        FORMAT_VERSION,
        record.name_len,
        record.key_len,
        record.kind as u8 | record.algorithm as u8,
        record.digits,
        record.properties.bits(),
    ]);
    let key_at = HEADER_BYTES + record.name().len();
    let counter_at = key_at + record.key().len();
    out[HEADER_BYTES..key_at].copy_from_slice(record.name());
    out[key_at..counter_at].copy_from_slice(record.key());
    out[counter_at..counter_at + COUNTER_BYTES].copy_from_slice(&record.moving_factor);
    counter_at + COUNTER_BYTES
}
pub fn decode(bytes: &[u8]) -> Result<Credential, Error> {
    if bytes.len() != length(bytes)? {
        return Err(Error::Invalid);
    }
    let kind = Kind::from_byte(bytes[TYPE])?;
    let key_at = HEADER_BYTES + bytes[NAME_LENGTH] as usize;
    let counter_at = key_at + bytes[KEY_LENGTH] as usize;
    Credential::new(
        &bytes[HEADER_BYTES..key_at],
        &bytes[key_at..counter_at],
        kind,
        Algorithm::from_byte(bytes[TYPE] & Kind::ALGORITHM_MASK)?,
        bytes[DIGITS],
        Properties::new(bytes[PROPERTIES])?,
        bytes[counter_at..].try_into().map_err(|_| Error::Invalid)?,
    )
}
