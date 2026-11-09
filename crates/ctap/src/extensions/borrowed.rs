// SPDX-License-Identifier: Apache-2.0
//! Borrowed base extension profile: credProtect and hmac-secret only.
use super::Field;
use crate::request::{Error, credential::borrowed::Reader, hmac_secret};
#[derive(Default)]
pub struct Input<'a> {
    pub protection: Option<u8>,
    pub create_secret: bool,
    pub secret: Option<&'a [u8]>,
}
impl<'a> Input<'a> {
    pub fn decode<R: Reader<'a>>(bytes: &'a [u8], make: bool) -> Result<Self, R::Error> {
        let mut input = Self::default();
        let mut reader = R::new(bytes);
        for _ in 0..reader.map()? {
            match super::field(reader.text()?.as_bytes(), make) {
                Some(Field::Protection) => {
                    let raw = reader.item()?;
                    let value = R::new(raw)
                        .uint()
                        .map_err(|_| R::Error::INVALID_PARAMETER)?;
                    input.protection = Some(super::protection::<R::Error>(value)?);
                }
                Some(Field::HmacSecret) if make => input.create_secret = reader.boolean()?,
                Some(Field::HmacSecret) => {
                    let bytes = reader.item()?;
                    hmac_secret::borrowed::Parameters::decode::<R>(bytes)?;
                    input.secret = Some(bytes);
                }
                _ => {
                    reader.item()?;
                }
            }
        }
        Ok(input)
    }
}
