// SPDX-License-Identifier: Apache-2.0
//! Semantic offsets into the owned, authenticated envelope. Framing errors
//! retain precedence over these deferred management-schema errors.
use super::{Error, Fields, User};
use crate::{
    credential,
    request::stream::{is_cbor_container, skip_cbor_event},
};
const VENDOR_METADATA_ONLY: u64 = super::VENDOR_METADATA_ONLY as u64;
use canokey_protocol::cbor::Event;

#[derive(Clone, Copy, Default)]
struct Span {
    start: u16,
    len: u16,
}
impl Span {
    const NONE: Self = Self { start: 0, len: 0 };
    fn bytes(self, raw: &[u8]) -> &[u8] {
        &raw[usize::from(self.start)..usize::from(self.start) + usize::from(self.len)]
    }
    fn optional(self, raw: &[u8]) -> Option<&[u8]> {
        (self.start != 0).then(|| self.bytes(raw))
    }
}

#[derive(Clone, Copy)]
pub struct Parsed<E: Error> {
    spans: [Span; 5], // RP hash, credential ID, user ID, name, display name.
    metadata_only: bool,
    error: Option<E>,
}
impl<E: Error> Parsed<E> {
    pub const fn new() -> Self {
        Self {
            spans: [Span::NONE; 5],
            metadata_only: false,
            error: None,
        }
    }
    pub fn fields<'a>(&self, raw: &'a [u8]) -> Result<Fields<'a>, E> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let [rp, id, user, name, display] = self.spans;
        Ok(Fields {
            rp: rp.optional(raw).map(|v| v.try_into().unwrap()),
            id: id.optional(raw).map(|v| v.try_into().unwrap()),
            user: if user.start == 0 {
                None
            } else {
                Some(User {
                    id: user.bytes(raw),
                    name: name.optional(raw).map(|v| core::str::from_utf8(v).unwrap()),
                    display: display
                        .optional(raw)
                        .map(|v| core::str::from_utf8(v).unwrap()),
                })
            },
            metadata_only: self.metadata_only,
        })
    }
}
pub struct Parser<E: Error, const PREFIX: usize> {
    error: core::marker::PhantomData<E>,
    previous: Option<u64>,
    key: Option<u64>,
    entity: u8,
    member: u8,
    value: bool,
    text: Span,
    previous_text: Span,
    text_kind: u8, // 1: member name, 2: credential type.
    public_key: bool,
    skip: u8,
}
impl<E: Error, const PREFIX: usize> Parser<E, PREFIX> {
    pub const fn new() -> Self {
        Self {
            error: core::marker::PhantomData,
            previous: None,
            key: None,
            entity: 0,
            member: 0,
            value: false,
            text: Span::NONE,
            previous_text: Span::NONE,
            text_kind: 0,
            public_key: false,
            skip: 0,
        }
    }
    pub fn event(
        &mut self,
        p: &mut Parsed<E>,
        raw: &[u8],
        event: &Event<'_>,
        depth: u8,
        offset: usize,
    ) {
        if p.error.is_none() {
            p.error = self.consume(p, raw, event, depth, offset).err();
        }
    }
    fn consume(
        &mut self,
        p: &mut Parsed<E>,
        raw: &[u8],
        event: &Event<'_>,
        depth: u8,
        offset: usize,
    ) -> Result<(), E> {
        if skip_cbor_event(&mut self.skip, event)? {
            return Ok(());
        }
        let span = |len| Span {
            start: (PREFIX + offset) as u16,
            len,
        };
        if depth == 1 {
            let Some(key) = self.key.take() else {
                if matches!(event, Event::End) {
                    return Ok(());
                }
                let Event::Unsigned(key) = *event else {
                    return Err(E::UNEXPECTED_TYPE);
                };
                if self.previous.is_some_and(|old| key <= old) {
                    return Err(E::INVALID_CBOR);
                }
                self.previous = Some(key);
                self.key = Some(key);
                return Ok(());
            };
            self.entity = 0;
            match (key, *event) {
                (1, Event::Bytes(32)) => p.spans[0] = span(32),
                (1, Event::Bytes(_)) => return Err(E::INVALID_LENGTH),
                (2 | 3, Event::Map(_)) => {
                    self.entity = key as u8;
                    self.previous_text = Span::NONE;
                    self.value = false;
                }
                (VENDOR_METADATA_ONLY, Event::Bool(value)) => p.metadata_only = value,
                (1..=3 | VENDOR_METADATA_ONLY, _) => return Err(E::UNEXPECTED_TYPE),
                _ => {
                    if is_cbor_container(event) {
                        self.skip = 1;
                    }
                }
            }
        } else if self.entity != 0 && depth == 2 {
            if self.value {
                self.value = false;
                match (self.entity, self.member, *event) {
                    (2, 1, Event::Bytes(n)) => {
                        if usize::from(n) != core::mem::size_of::<credential::Id>() {
                            return Err(E::NO_CREDENTIALS);
                        }
                        p.spans[1] = span(n);
                    }
                    (2, 2, Event::Text(n)) => {
                        self.text = span(n);
                        self.text_kind = 2;
                    }
                    (3, 1, Event::Bytes(n @ 1..=64)) => p.spans[2] = span(n),
                    (3, 1, Event::Bytes(_)) => return Err(E::INVALID_LENGTH),
                    (3, m @ (3 | 4), Event::Text(n)) => p.spans[usize::from(m)] = span(n),
                    (_, 0, _) => {
                        if is_cbor_container(event) {
                            self.skip = 1;
                        }
                    }
                    _ => return Err(E::UNEXPECTED_TYPE),
                }
            } else {
                match *event {
                    Event::Text(n) => {
                        self.text = span(n);
                        self.text_kind = 1;
                    }
                    Event::End => {
                        if (self.entity == 2 && (!self.public_key || p.spans[1].start == 0))
                            || (self.entity == 3 && p.spans[2].start == 0)
                        {
                            return Err(E::MISSING_PARAMETER);
                        }
                        self.entity = 0;
                    }
                    _ => return Err(E::UNEXPECTED_TYPE),
                }
            }
        } else if depth == 3 && matches!(event, Event::End) && self.text_kind != 0 {
            let text = self.text.bytes(raw);
            if self.text_kind == 1 {
                let old = self.previous_text;
                if old.start != 0 && (self.text.len, text) <= (old.len, old.bytes(raw)) {
                    return Err(E::INVALID_CBOR);
                }
                self.previous_text = self.text;
                self.member = match text {
                    b"id" => 1,
                    b"type" if self.entity == 2 => 2,
                    b"name" if self.entity == 3 => 3,
                    b"displayName" if self.entity == 3 => 4,
                    _ => 0,
                };
                self.value = true;
            } else {
                self.public_key = text == b"public-key";
            }
            self.text_kind = 0;
        }
        Ok(())
    }
}
