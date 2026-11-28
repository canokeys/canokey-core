// SPDX-License-Identifier: Apache-2.0
//! GetInfo encoding over a product's immutable schema and current card state.
use canokey_protocol::cbor::{EncodeError, Encoder};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Flag {
    AlwaysUv,
    ForceChange,
    Nfc,
    ClientPin,
    LongReset,
}
#[derive(Clone, Copy, Debug)]
pub enum Value {
    Aaguid,
    AlwaysUv,
    ClientPin,
    MakeCredUvNotRqd,
    ForceChange,
    MinimumPinLength,
    RemainingCredentials,
    LongReset,
    Algorithm,
    /// The shared `extensions::NAMES` array; fixed, but stored only once.
    Extensions,
    /// The shared `"type": "public-key"` algorithm member.
    PublicKeyType,
}
/// The immutable schema is one Flash byte string of operations:
/// `1..=LITERAL_MAX` is that many following pre-encoded CBOR bytes; [`when`]
/// makes only the next literal conditional on a flag; [`value`] emits card
/// state. Literals contain complete CBOR prefixes or members; no runtime
/// parser, heap or response copy is needed.
pub const LITERAL_MAX: usize = 0x7f;
const WHEN: u8 = 0x80;
const BOOLEAN: u8 = 0x90;
const NEGATE: u8 = 0x08;
const AAGUID: u8 = 0xa0;
const MINIMUM: u8 = 0xa1;
const REMAINING: u8 = 0xa2;
const ALGORITHM: u8 = 0xa3;
const EXTENSIONS: u8 = 0xa4;
const PUBLIC_KEY_TYPE: u8 = 0xa5;
pub const fn when(flag: Flag, set: bool) -> u8 {
    WHEN | if set { 0 } else { NEGATE } | flag as u8
}
pub const fn value(value: Value) -> u8 {
    match value {
        Value::Aaguid => AAGUID,
        Value::AlwaysUv => BOOLEAN | Flag::AlwaysUv as u8,
        Value::ClientPin => BOOLEAN | Flag::ClientPin as u8,
        Value::MakeCredUvNotRqd => BOOLEAN | NEGATE | Flag::AlwaysUv as u8,
        Value::ForceChange => BOOLEAN | Flag::ForceChange as u8,
        Value::MinimumPinLength => MINIMUM,
        Value::RemainingCredentials => REMAINING,
        Value::LongReset => BOOLEAN | Flag::LongReset as u8,
        Value::Algorithm => ALGORITHM,
        Value::Extensions => EXTENSIONS,
        Value::PublicKeyType => PUBLIC_KEY_TYPE,
    }
}
pub struct State<'a> {
    pub aaguid: &'a [u8; 16],
    pub always_uv: bool,
    pub client_pin: bool,
    pub force_change: bool,
    pub minimum_pin_length: u8,
    pub remaining_credentials: u8,
    pub long_reset: bool,
    pub nfc: bool,
    pub algorithm: i32,
}
/// Synchronous output borrow. Each operation preserves its encoder's bounded
/// write/error semantics; this capability cannot execute an application.
pub trait Sink {
    type Error;
    fn encoded(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    fn boolean(&mut self, value: bool) -> Result<(), Self::Error>;
    fn unsigned(&mut self, value: u8) -> Result<(), Self::Error>;
    fn signed(&mut self, value: i32) -> Result<(), Self::Error>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), Self::Error>;
}
impl Sink for Encoder<&mut [u8]> {
    type Error = EncodeError;
    fn encoded(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.encoded(bytes).finish()
    }
    fn boolean(&mut self, value: bool) -> Result<(), EncodeError> {
        self.bool(value).finish()
    }
    fn unsigned(&mut self, value: u8) -> Result<(), EncodeError> {
        self.u8(value).finish()
    }
    fn signed(&mut self, value: i32) -> Result<(), EncodeError> {
        self.i32(value).finish()
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        self.bytes(value).finish()
    }
}
pub fn encode<S: Sink>(mut schema: &[u8], state: &State<'_>, sink: &mut S) -> Result<(), S::Error> {
    let flags = u8::from(state.always_uv) << Flag::AlwaysUv as u8
        | u8::from(state.force_change) << Flag::ForceChange as u8
        | u8::from(state.nfc) << Flag::Nfc as u8
        | u8::from(state.client_pin) << Flag::ClientPin as u8
        | u8::from(state.long_reset) << Flag::LongReset as u8;
    let mut emit = true;
    while let Some((&op, rest)) = schema.split_first() {
        schema = rest;
        // Flag operations select a state bit and optionally negate it.
        let test = ((flags >> (op & 7)) ^ (op >> 3)) & 1 != 0;
        if op < WHEN {
            // A truncated schema ends encoding.
            let (bytes, rest) = rest.split_at_checked(usize::from(op)).unwrap_or_default();
            if emit {
                sink.encoded(bytes)?;
            }
            emit = true;
            schema = rest;
        } else if op < BOOLEAN {
            emit = test;
        } else if op < AAGUID {
            sink.boolean(test)?;
        } else if op == AAGUID {
            sink.bytes(state.aaguid)?;
        } else if op == MINIMUM {
            sink.unsigned(state.minimum_pin_length)?;
        } else if op == REMAINING {
            sink.unsigned(state.remaining_credentials)?;
        } else if op == ALGORITHM {
            sink.signed(state.algorithm)?;
        } else {
            sink.encoded(if op == EXTENSIONS {
                &crate::extensions::NAMES
            } else {
                &crate::response::encoding::PUBLIC_KEY_TYPE
            })?;
        }
    }
    Ok(())
}
