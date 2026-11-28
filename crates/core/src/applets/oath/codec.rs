// SPDX-License-Identifier: Apache-2.0
//! Credential RAM view: header6, name64, key64 and counter8, unused bytes zero.
//! Storage packs the same fields as header6, name, key and counter8.
//! Storage identity belongs to the repository, not this codec.
use super::{
    Algorithm, Error,
    credential::{Credential, Kind, Properties},
};
pub(super) const FORMAT_VERSION: u8 = 2;
pub(super) const VERSION: usize = 0;
pub(super) const NAME_LENGTH: usize = 1;
pub(super) const KEY_LENGTH: usize = 2;
pub(super) const TYPE: usize = 3;
pub(super) const DIGITS: usize = 4;
pub(super) const PROPERTIES: usize = 5;
pub const HEADER_BYTES: usize = 6;
pub const COUNTER_BYTES: usize = 8;
pub const FIXED_BYTES: usize = HEADER_BYTES + COUNTER_BYTES;
pub use super::credential::{KEY_LIMIT, NAME_LIMIT};
pub const LENGTH: usize = FIXED_BYTES + NAME_LIMIT + KEY_LIMIT;
pub(super) const KEY_OFFSET: usize = HEADER_BYTES + NAME_LIMIT;
pub(super) const COUNTER_OFFSET: usize = KEY_OFFSET + KEY_LIMIT;
pub fn length(header: &[u8]) -> Result<usize, Error> {
    if header.len() < HEADER_BYTES
        || header[VERSION] != FORMAT_VERSION
        || header[NAME_LENGTH] < 1
        || header[NAME_LENGTH] > NAME_LIMIT as u8
        || header[KEY_LENGTH] < 1
        || header[KEY_LENGTH] > KEY_LIMIT as u8
    {
        return Err(Error::Invalid);
    }
    Ok(LENGTH)
}
/// Stored length of a validated header: header, name, key and counter with no
/// padding to the name and key limits.
pub fn stored_length(header: &[u8]) -> Result<usize, Error> {
    length(header)?;
    Ok(FIXED_BYTES + usize::from(header[NAME_LENGTH]) + usize::from(header[KEY_LENGTH]))
}
/// Pack the fixed RAM view into its stored form and return the stored length.
pub fn encode(record: &Credential, out: &mut [u8; LENGTH]) -> usize {
    let name_end = HEADER_BYTES + usize::from(record.bytes[NAME_LENGTH]);
    let key = record.key();
    let key_end = name_end + key.len();
    out[..name_end].copy_from_slice(&record.bytes[..name_end]);
    out[name_end..key_end].copy_from_slice(key);
    out[key_end..key_end + COUNTER_BYTES].copy_from_slice(&record.bytes[COUNTER_OFFSET..]);
    key_end + COUNTER_BYTES
}
/// Validated non-secret fields.
pub(super) struct Header {
    pub name_len: u8,
    pub kind: Kind,
    pub digits: u8,
    pub properties: Properties,
}
// Callers first validate the record shape with length(); the repository keeps
// that proof in its private Entry alongside these six bytes.
pub(super) fn fields(bytes: &[u8; HEADER_BYTES]) -> Result<Header, Error> {
    Algorithm::from_byte(bytes[TYPE] & Kind::ALGORITHM_MASK)?;
    let header = Header {
        name_len: bytes[NAME_LENGTH],
        kind: Kind::from_byte(bytes[TYPE])?,
        digits: bytes[DIGITS],
        properties: Properties::new(bytes[PROPERTIES])?,
    };
    if header.digits < 4 || header.digits > 8 {
        return Err(Error::Invalid);
    }
    Ok(header)
}
pub(super) fn validate(bytes: &[u8; LENGTH]) -> Result<(), Error> {
    length(bytes)?;
    fields(bytes[..HEADER_BYTES].try_into().unwrap())?;
    Ok(())
}
/// Expand one stored credential, the inverse of `encode`.
pub fn decode(bytes: &[u8]) -> Result<Credential, Error> {
    if stored_length(bytes)? != bytes.len() {
        return Err(Error::Invalid);
    }
    let name_end = HEADER_BYTES + usize::from(bytes[NAME_LENGTH]);
    let key_end = name_end + usize::from(bytes[KEY_LENGTH]);
    let mut record = Credential { bytes: [0; LENGTH] };
    record.bytes[..name_end].copy_from_slice(&bytes[..name_end]);
    record.bytes[KEY_OFFSET..KEY_OFFSET + key_end - name_end]
        .copy_from_slice(&bytes[name_end..key_end]);
    record.bytes[COUNTER_OFFSET..].copy_from_slice(&bytes[key_end..]);
    validate(&record.bytes)?;
    Ok(record)
}
