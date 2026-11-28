// SPDX-License-Identifier: Apache-2.0
//! Standard extension mechanisms over product-owned secrets and buffers.
pub mod hmac_secret;

pub mod borrowed;
pub(crate) use crate::request::credential::schema::Field;

/// Supported extension identifiers in lexical order, pre-encoded as GetInfo's
/// CBOR array. Request parsing, response maps and GetInfo share this one copy.
pub static NAMES: [u8; 93] = *b"\x87\x68credBlob\x6bcredProtect\x6bhmac-secret\x6ehmac-secret-mc\
\x6clargeBlobKey\x6cminPinLength\x71thirdPartyPayment";
/// Indexes [`NAMES`] after its array header.
#[derive(Clone, Copy)]
pub enum Extension {
    CredBlob,
    CredProtect,
    HmacSecret,
    HmacSecretMc,
    LargeBlobKey,
    MinPinLength,
    ThirdPartyPayment,
}
/// Pre-encoded CBOR text key for `extension`; offsets fold at compile time.
#[inline(always)]
pub fn name(extension: Extension) -> &'static [u8] {
    const SPANS: [(usize, usize); 7] = {
        let mut spans = [(0, 0); 7];
        let mut at = 1;
        let mut index = 0;
        while index < spans.len() {
            let end = at + 1 + (NAMES[at] & 0x1f) as usize;
            spans[index] = (at, end);
            at = end;
            index += 1;
        }
        assert!(at == NAMES.len() && NAMES[0] == 0x80 | spans.len() as u8);
        spans
    };
    let (start, end) = SPANS[extension as usize];
    &NAMES[start..end]
}
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
