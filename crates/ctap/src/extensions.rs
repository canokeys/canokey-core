// SPDX-License-Identifier: Apache-2.0
//! Standard extension mechanisms over product-owned secrets and buffers.
pub mod hmac_secret;

pub mod borrowed;
pub(crate) use crate::request::credential::schema::Field;
/// Reuse the CanoKey request classifier for the borrowed base profile. The
/// enclosing product still selects which standard extensions it implements.
pub(crate) fn field(key: &[u8], make: bool) -> Option<Field> {
    use crate::request::credential::schema::{self, Context};
    let field = schema::text_field(Context::Extensions, key, make);
    if matches!(field, Field::Ignore) {
        None
    } else {
        Some(field)
    }
}
#[inline(always)]
pub fn protection<E: crate::request::Error>(value: u64) -> Result<u8, E> {
    if (1..=3).contains(&value) {
        Ok(value as u8)
    } else {
        Err(E::INVALID_PARAMETER)
    }
}
