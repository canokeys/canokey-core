// SPDX-License-Identifier: Apache-2.0
//! GetInfo encoding over a product's immutable schema and current card state.
use canokey_protocol::cbor::{EncodeError, Encoder};

#[derive(Clone, Copy, Debug)]
pub enum Flag {
    AlwaysUv,
    ForceChange,
    Nfc,
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
}
/// Schema parts live in Flash. Conditional fragments contain complete CBOR
/// prefixes or members; no runtime parser, heap or response copy is needed.
pub enum Part {
    Encoded(&'static [u8]),
    Choice(Flag, &'static [u8], &'static [u8]),
    Value(Value),
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
pub fn encode<S: Sink>(schema: &[Part], state: &State<'_>, sink: &mut S) -> Result<(), S::Error> {
    for part in schema {
        match part {
            Part::Encoded(bytes) => sink.encoded(bytes)?,
            Part::Choice(flag, yes, no) => {
                let enabled = match flag {
                    Flag::AlwaysUv => state.always_uv,
                    Flag::ForceChange => state.force_change,
                    Flag::Nfc => state.nfc,
                };
                sink.encoded(if enabled { yes } else { no })?;
            }
            Part::Value(value) => match value {
                Value::Aaguid => sink.bytes(state.aaguid)?,
                Value::AlwaysUv => sink.boolean(state.always_uv)?,
                Value::ClientPin => sink.boolean(state.client_pin)?,
                Value::MakeCredUvNotRqd => sink.boolean(!state.always_uv)?,
                Value::ForceChange => sink.boolean(state.force_change)?,
                Value::MinimumPinLength => sink.unsigned(state.minimum_pin_length)?,
                Value::RemainingCredentials => sink.unsigned(state.remaining_credentials)?,
                Value::LongReset => sink.boolean(state.long_reset)?,
                Value::Algorithm => sink.signed(state.algorithm)?,
            },
        }
    }
    Ok(())
}
