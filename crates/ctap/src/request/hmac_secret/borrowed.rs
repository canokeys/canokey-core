// SPDX-License-Identifier: Apache-2.0
//! Borrowed hmac-secret ciphertext/authentication with one structural point.
use super::{KEY_AGREEMENT, PIN_PROTOCOL, SALT_AUTH, SALT_ENC, admit_body, admit_fields};
use crate::{
    client_pin::{
        Protocol,
        agreement::{COORDINATE_BYTES, Field, POINT_BYTES, REQUIRED_FIELDS},
    },
    request::{Error, credential::borrowed::Reader, stream::Key},
};

pub struct Parameters<'a> {
    pub agreement: [u8; POINT_BYTES],
    pub salt: &'a [u8],
    pub auth: &'a [u8],
    pub protocol: Protocol,
}
fn agreement<'a, R: Reader<'a>>(
    reader: &mut R,
    point: &mut [u8; POINT_BYTES],
) -> Result<(), R::Error> {
    let mut seen = 0x00;
    let mut previous = None;
    for _ in 0..reader.map()? {
        let key = Key::<R::Error>::borrowed_ordered(reader, &mut previous)?;
        let Some(field) = key.and_then(|key| Field::decode(i64::from(key))) else {
            reader.skip_unknown()?;
            continue;
        };
        if let Some(expected) = field.scalar() {
            if Key::<R::Error>::borrowed(reader)?.map(i64::from) != Some(expected) {
                return Err(R::Error::INVALID_PARAMETER);
            }
        } else {
            let coordinate = reader.bytes_checked(|length| {
                if length == COORDINATE_BYTES {
                    Ok(())
                } else {
                    Err(R::Error::INVALID_PARAMETER)
                }
            })?;
            let offset = field.coordinate_offset().unwrap();
            point[offset..offset + COORDINATE_BYTES].copy_from_slice(coordinate);
        }
        seen |= field.bit();
    }
    if seen != REQUIRED_FIELDS {
        return Err(R::Error::MISSING_PARAMETER);
    }
    Ok(())
}
impl<'a> Parameters<'a> {
    /// The enclosing CTAP reader validates framing, duplicate keys and ordering.
    /// Decoding only checks structure; point validation waits for actual ECDH.
    pub fn decode<R: Reader<'a>>(bytes: &'a [u8]) -> Result<Self, R::Error> {
        let mut reader = R::new(bytes);
        let parameters = Self::read(&mut reader)?;
        if !reader.done() {
            return Err(R::Error::INVALID_CBOR);
        }
        Ok(parameters)
    }
    pub fn read<R: Reader<'a>>(reader: &mut R) -> Result<Self, R::Error> {
        let mut point = [0x00; POINT_BYTES];
        let (mut salt, mut auth, mut protocol, mut seen) = (&[][..], &[][..], Protocol::One, 0x00);
        let mut previous = None;
        for _ in 0..reader.map()? {
            match Key::<R::Error>::borrowed_ordered(reader, &mut previous)? {
                Some(KEY_AGREEMENT) => {
                    agreement(reader, &mut point)?;
                    seen |= 0x01;
                }
                Some(SALT_ENC) => {
                    salt =
                        reader.bytes_checked(|length| admit_body::<R::Error>(SALT_ENC, length))?;
                    seen |= 0x02;
                }
                Some(SALT_AUTH) => {
                    auth =
                        reader.bytes_checked(|length| admit_body::<R::Error>(SALT_AUTH, length))?;
                    seen |= 0x04;
                }
                Some(PIN_PROTOCOL) => {
                    let value = reader.parameter_uint()?;
                    protocol = Protocol::decode(value).ok_or(R::Error::INVALID_PARAMETER)?;
                }
                _ => {
                    reader.skip_unknown()?;
                }
            }
        }
        admit_fields::<R::Error>(seen, protocol, salt.len(), auth.len())?;
        Ok(Self {
            agreement: point,
            salt,
            auth,
            protocol,
        })
    }
}
