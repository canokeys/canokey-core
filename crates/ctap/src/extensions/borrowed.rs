// SPDX-License-Identifier: Apache-2.0
//! Borrowed base extension profile: credProtect and hmac-secret only.
use super::Field;
use crate::request::{Error, credential::borrowed::Reader, hmac_secret, stream::TextOrder};
#[derive(Default)]
pub struct Input<'a> {
    pub protection: Option<u8>,
    pub create_secret: bool,
    pub secret: Option<&'a [u8]>,
}
impl<'a> Input<'a> {
    pub fn decode<R: Reader<'a>>(bytes: &'a [u8], make: bool) -> Result<Self, R::Error> {
        let mut reader = R::new(bytes);
        let input = Self::read(&mut reader, make)?;
        if !reader.done() {
            return Err(R::Error::INVALID_CBOR);
        }
        Ok(input)
    }
    pub fn read<R: Reader<'a>>(reader: &mut R, make: bool) -> Result<Self, R::Error> {
        let mut input = Self::default();
        let mut order = TextOrder::new();
        for _ in 0..reader.map()? {
            match super::field(order.next(reader)?.as_bytes(), make) {
                Some(Field::Protection) => {
                    let value = reader.parameter_uint()?;
                    input.protection = Some(super::protection::<R::Error>(value)?);
                }
                Some(Field::HmacSecret) if make => input.create_secret = reader.boolean()?,
                Some(Field::HmacSecret) => {
                    let before = reader.remaining();
                    hmac_secret::borrowed::Parameters::read(reader)?;
                    input.secret = Some(&before[..before.len() - reader.remaining().len()]);
                }
                _ => {
                    reader.skip_unknown()?;
                }
            }
        }
        Ok(input)
    }
}
