// SPDX-License-Identifier: Apache-2.0
//! Fixed credential encoding: header6, name64, key64 and counter8.
//! Storage identity belongs to the repository, not this codec.
use super::{
    Algorithm, Error,
    credential::{Credential, Kind, Properties},
};
pub(super) const FORMAT_VERSION: u8 = 2;
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
pub(super) const KEY_OFFSET: usize = HEADER_BYTES + NAME_LIMIT;
pub(super) const COUNTER_OFFSET: usize = KEY_OFFSET + KEY_LIMIT;
pub fn length(header: &[u8]) -> Result<usize, Error> {
    if header.len() < HEADER_BYTES
        || header[VERSION] != FORMAT_VERSION
        || !(1..=NAME_LIMIT as u8).contains(&header[NAME_LENGTH])
        || !(1..=KEY_LIMIT as u8).contains(&header[KEY_LENGTH])
    {
        return Err(Error::Invalid);
    }
    Ok(LENGTH)
}
pub fn encode(record: &Credential, out: &mut [u8; LENGTH]) -> usize {
    out.copy_from_slice(&record.bytes);
    LENGTH
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
    if !(4..=8).contains(&header.digits) {
        return Err(Error::Invalid);
    }
    Ok(header)
}
pub(super) fn validate(bytes: &[u8; LENGTH]) -> Result<(), Error> {
    length(bytes)?;
    fields(bytes[..HEADER_BYTES].try_into().unwrap())?;
    Ok(())
}
pub fn decode(bytes: &[u8]) -> Result<Credential, Error> {
    let bytes: &[u8; LENGTH] = bytes.try_into().map_err(|_| Error::Invalid)?;
    validate(bytes)?;
    let mut record = Credential { bytes: [0; LENGTH] };
    record.bytes.copy_from_slice(bytes);
    Ok(record)
}
