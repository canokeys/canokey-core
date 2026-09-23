// SPDX-License-Identifier: Apache-2.0
//! Internal version-1 credential encoding, independent of packed C structs.
//! Storage identity/tombstone policy belongs to the repository, not this codec.
use super::{
    Algorithm, Error,
    credential::{Credential, Kind, Properties},
};
pub const LENGTH: usize = 142;
pub fn encode(record: &Credential, out: &mut [u8; LENGTH]) {
    out.fill(0);
    out[..6].copy_from_slice(&[
        1,
        record.name_len,
        record.key_len,
        record.kind as u8 | record.algorithm as u8,
        record.digits,
        record.properties.bits(),
    ]);
    out[6..6 + record.name().len()].copy_from_slice(record.name());
    out[70..70 + record.key().len()].copy_from_slice(record.key());
    out[134..].copy_from_slice(&record.moving_factor);
}
pub fn decode(bytes: &[u8]) -> Result<Credential, Error> {
    if bytes.len() != LENGTH || bytes[0] != 1 || bytes[1] > 64 || bytes[2] > 64 {
        return Err(Error::Invalid);
    }
    let kind = match bytes[3] & 0xf0 {
        0x10 => Kind::Hotp,
        0x20 => Kind::Totp,
        _ => return Err(Error::Invalid),
    };
    Credential::new(
        &bytes[6..6 + usize::from(bytes[1])],
        &bytes[70..70 + usize::from(bytes[2])],
        kind,
        Algorithm::from_byte(bytes[3] & 15)?,
        bytes[4],
        Properties::new(bytes[5])?,
        bytes[134..].try_into().map_err(|_| Error::Invalid)?,
    )
}
