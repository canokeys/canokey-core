// SPDX-License-Identifier: Apache-2.0
//! Nested GENERAL AUTHENTICATE decoder. Long values are emitted immediately.
use super::wire::{ga_field, ga_tag};
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::length::{Feed, LengthState},
};
// Callback contract: Some(length) announces a field (including empty fields);
// None delivers the next borrowed value chunk. Consumers must not retain it.
type Emit<'a> = dyn FnMut(u8, Option<usize>, &[u8]) -> Result<(), Sw> + 'a;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    OuterTag,
    OuterLength,
    Tag,
    Length,
    Value,
}
pub struct Ga {
    phase: Phase,
    length: LengthState,
    // Bytes left inside the outer 7C value, including nested TLV headers.
    remaining: usize,
    tag: usize,
    n: usize,
    offset: usize,
    pub used: usize,
    // (offset, length) in concatenated field VALUES, with TLV headers removed.
    // Some((_, 0)) is an explicit empty field; None means the tag was absent.
    pub fields: [Option<(usize, usize)>; ga_field::COUNT],
}
impl Ga {
    pub const fn new() -> Self {
        Self {
            phase: Phase::OuterTag,
            length: LengthState::Initial,
            remaining: 0,
            tag: 0,
            n: 0,
            offset: 0,
            used: 0,
            fields: [None; ga_field::COUNT],
        }
    }
    pub fn feed(&mut self, bytes: &[u8], out: &mut [u8]) -> Result<(), Sw> {
        let mut at = self.used;
        self.events(bytes, &mut |_, length, b| {
            if let Some(n) = length {
                if at + n > out.len() {
                    return Err(Sw::WRONG_LENGTH);
                }
            } else {
                out[at..at + b.len()].copy_from_slice(b);
                at += b.len();
            }
            Ok(())
        })
    }
    pub fn events(&mut self, mut bytes: &[u8], emit: &mut Emit<'_>) -> Result<(), Sw> {
        while !bytes.is_empty() {
            if self.phase == Phase::Value {
                let n = (self.n - self.offset).min(bytes.len());
                if n > self.remaining {
                    return Err(Sw::WRONG_LENGTH);
                }
                emit(self.tag as u8 + ga_tag::WITNESS, None, &bytes[..n])?;
                self.remaining -= n;
                self.offset += n;
                self.used += n;
                bytes = &bytes[n..];
                if self.offset == self.n {
                    self.phase = Phase::Tag;
                }
                continue;
            }
            let b = bytes[0];
            bytes = &bytes[1..];
            if matches!(self.phase, Phase::Tag | Phase::Length | Phase::Value) {
                if self.remaining == 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                self.remaining -= 1;
            }
            match self.phase {
                Phase::OuterTag => {
                    if b != ga_tag::TEMPLATE {
                        return Err(Sw::WRONG_DATA);
                    }
                    self.phase = Phase::OuterLength;
                }
                Phase::OuterLength => match self.length.feed(b) {
                    Feed::Invalid => return Err(Sw::WRONG_DATA),
                    Feed::More => (),
                    Feed::Complete(n) => {
                        self.remaining = n as usize;
                        self.phase = Phase::Tag;
                    }
                },
                Phase::Tag => {
                    if !(ga_tag::WITNESS..=ga_tag::EXPONENTIATION).contains(&b) {
                        return Err(Sw::WRONG_DATA);
                    }
                    self.tag = (b - ga_tag::WITNESS) as usize;
                    if self.fields[self.tag].is_some() {
                        return Err(Sw::WRONG_DATA);
                    }
                    self.length = LengthState::Initial;
                    self.phase = Phase::Length;
                }
                Phase::Length => match self.length.feed(b) {
                    Feed::Invalid => return Err(Sw::WRONG_DATA),
                    Feed::More => (),
                    Feed::Complete(n) => {
                        self.n = n as usize;
                        if self.n > self.remaining {
                            return Err(Sw::WRONG_LENGTH);
                        }
                        emit(self.tag as u8 + ga_tag::WITNESS, Some(self.n), &[])?;
                        self.fields[self.tag] = Some((self.used, self.n));
                        self.offset = 0;
                        self.phase = if n == 0 { Phase::Tag } else { Phase::Value };
                    }
                },
                Phase::Value => unreachable!("value chunks are handled above"),
            }
        }
        Ok(())
    }
    pub fn finish(&self) -> Result<(), Sw> {
        if self.phase != Phase::Tag || self.remaining != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(())
    }
}
