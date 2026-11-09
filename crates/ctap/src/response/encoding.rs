// SPDX-License-Identifier: Apache-2.0
//! Standard response schemas over a bounded caller-owned encoder.
use crate::{credential, resident};
pub use canokey_protocol::cbor::{EncodeError, Encoder};

include!(concat!(env!("OUT_DIR"), "/ctap_response.rs"));

pub mod cose {
    pub const ES256: i32 = -7;
    pub const EDDSA: i32 = -8;
    pub const MLDSA65: i32 = canokey_ports::mldsa::DSA65.cose;
    pub const MLDSA44: i32 = canokey_ports::mldsa::DSA44.cose;
    pub const CRV: i8 = -1;
    pub const X: i8 = -2;
    pub const Y: i8 = -3;
    pub const P256: i8 = 1;
}
// CTAP 2.1 credential-management response labels; byte keys in canonical order.
pub mod management {
    pub const USER: u8 = 0x06;
    pub const DESCRIPTOR: u8 = 0x07;
    pub const TOTAL_CREDENTIALS: u8 = 0x09;
    pub const CRED_PROTECT: u8 = 0x0a;
    pub const LARGE_BLOB_KEY: u8 = 0x0b;
    pub const THIRD_PARTY_PAYMENT: u8 = 0x0c;
}
pub mod make_response {
    // Format/authData labels are carried by generated MAKE_HEADER.
    pub const ATTESTATION: u8 = 0x03;
    pub const LARGE_BLOB_KEY: u8 = 0x05;
}
pub mod assertion_response {
    pub const CREDENTIAL: u8 = 0x01;
    pub const AUTH_DATA: u8 = 0x02;
    pub const SIGNATURE: u8 = 0x03;
    pub const USER: u8 = 0x04;
    pub const COUNT: u8 = 0x05;
    pub const LARGE_BLOB_KEY: u8 = 0x07;
}

use management as cm;
// These boundaries share the schema across authentication and management.
#[inline(never)]
pub fn descriptor(e: &mut Encoder<&mut [u8]>, id: &[u8]) -> Result<(), EncodeError> {
    e.encoded(DESCRIPTOR).bytes(id).encoded(PUBLIC_KEY_TYPE);
    e.finish()
}

#[inline(never)]
pub fn user(
    e: &mut Encoder<&mut [u8]>,
    entry: &resident::Entry<'_>,
    details: bool,
) -> Result<(), EncodeError> {
    user_fields(e, entry.user, entry.name, entry.display, details)
}
#[inline(always)]
pub fn user_fields(
    e: &mut Encoder<&mut [u8]>,
    id: &[u8],
    name: &str,
    display: &str,
    details: bool,
) -> Result<(), EncodeError> {
    let has_name = details && !name.is_empty();
    let has_display = details && !display.is_empty();
    e.map(1 + u64::from(has_name) + u64::from(has_display))
        .encoded(USER_ID)
        .bytes(id);
    if has_name {
        e.encoded(USER_NAME).str(name);
    }
    if has_display {
        e.encoded(USER_DISPLAY).str(display);
    }
    e.finish()
}

// Classic and streamed PQ management responses share the same envelope.
// Keep these schemas out of line so both callers use one encoder path.
#[inline(never)]
pub fn management_header(
    e: &mut Encoder<&mut [u8]>,
    entry: &resident::Entry<'_>,
    first: bool,
    has_blob_key: bool,
) -> Result<(), EncodeError> {
    e.map(5 + u64::from(first) + u64::from(has_blob_key))
        .u8(cm::USER);
    user(e, entry, true)?;
    e.u8(cm::DESCRIPTOR);
    descriptor(e, entry.id)
}

#[inline(never)]
pub fn management_tail(
    e: &mut Encoder<&mut [u8]>,
    id: &credential::Id,
    total: Option<u8>,
    blob_key: Option<&[u8]>,
) -> Result<(), EncodeError> {
    if let Some(total) = total {
        e.u8(cm::TOTAL_CREDENTIALS).u8(total);
    }
    e.u8(cm::CRED_PROTECT)
        .u8(id[1] & credential::CRED_PROTECT_MASK);
    if let Some(key) = blob_key {
        e.u8(cm::LARGE_BLOB_KEY).bytes(key);
    }
    e.u8(cm::THIRD_PARTY_PAYMENT)
        .bool(id[1] & credential::THIRD_PARTY_PAYMENT != 0);
    e.finish()
}

/// COSE EC2 key: kty(1)=2, alg(3), crv(-1), x(-2), y(-3).
/// Product crypto validates the supplied 64-byte affine point.
#[inline(always)]
pub fn ec2(
    e: &mut Encoder<&mut [u8]>,
    algorithm: i32,
    curve: i32,
    public: &[u8],
) -> Result<(), EncodeError> {
    e.encoded(COSE_EC2)
        .i32(algorithm)
        .i8(cose::CRV)
        .i32(curve)
        .i8(cose::X)
        .bytes(&public[..32])
        .i8(cose::Y)
        .bytes(&public[32..64]);
    e.finish()
}
/// COSE OKP key: kty(1)=1, alg(3)=-8, crv(-1)=6, x(-2).
#[inline(always)]
pub fn ed25519(e: &mut Encoder<&mut [u8]>, public: &[u8]) -> Result<(), EncodeError> {
    e.encoded(COSE_ED25519).bytes(&public[..32]);
    e.finish()
}
#[inline(always)]
pub fn mldsa_header(algorithm: u8) -> Result<&'static [u8], EncodeError> {
    match algorithm {
        canokey_ports::alg::MLDSA65 => Ok(COSE_MLDSA65),
        canokey_ports::alg::MLDSA44 => Ok(COSE_MLDSA44),
        _ => Err(EncodeError),
    }
}
/// AKP public-key byte string header; the owner may stream its body afterwards.
#[inline(always)]
pub fn mldsa_public_header(e: &mut Encoder<&mut [u8]>, algorithm: u8) -> Result<(), EncodeError> {
    let params = canokey_ports::mldsa::parameters(algorithm).ok_or(EncodeError)?;
    e.encoded(mldsa_header(algorithm)?)
        .bytes_len(params.public_bytes as u64);
    e.finish()
}
/// Packed self-attestation map followed by the signature key, no signature body.
#[inline(always)]
pub fn self_attestation(e: &mut Encoder<&mut [u8]>, algorithm: i32) -> Result<(), EncodeError> {
    e.encoded(SELF_ATTESTATION).i32(algorithm).str("sig");
    e.finish()
}
