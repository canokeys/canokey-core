// SPDX-License-Identifier: Apache-2.0
//! Semantic offsets into the owned, authenticated envelope. Framing errors
//! retain precedence over these deferred management-schema errors.
use super::{Fields, Status, User, credential};
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

pub(in crate::applets::ctap) struct Parsed {
    spans: [Span; 5], // RP hash, credential ID, user ID, name, display name.
    metadata_only: bool,
    error: Option<Status>,
}
impl Parsed {
    pub const fn new() -> Self {
        Self {
            spans: [Span::NONE; 5],
            metadata_only: false,
            error: None,
        }
    }
    pub fn relocate(&mut self, start: usize) {
        for span in &mut self.spans {
            if span.start != 0 {
                span.start -= start as u16;
            }
        }
    }
    pub fn fields<'a>(&self, raw: &'a [u8]) -> Result<Fields<'a>, Status> {
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
pub(in crate::applets::ctap) struct Parser {
    previous: Option<u64>,
    key: Option<u64>,
    entity: u8,
    member: u8,
    value: bool,
    text: Span,
    previous_text: Span,
    text_kind: u8, // 1: member name, 2: credential type.
    public_key: bool,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            previous: None,
            key: None,
            entity: 0,
            member: 0,
            value: false,
            text: Span::NONE,
            previous_text: Span::NONE,
            text_kind: 0,
            public_key: false,
        }
    }
    pub fn event(
        &mut self,
        p: &mut Parsed,
        raw: &[u8],
        event: Event<'_>,
        depth: u8,
        offset: usize,
    ) {
        if p.error.is_none() {
            p.error = self.consume(p, raw, event, depth, offset).err();
        }
    }
    fn consume(
        &mut self,
        p: &mut Parsed,
        raw: &[u8],
        event: Event<'_>,
        depth: u8,
        offset: usize,
    ) -> Result<(), Status> {
        let span = |len| Span {
            start: (super::PREFIX + offset) as u16,
            len,
        };
        if depth == 1 {
            let Some(key) = self.key.take() else {
                if matches!(event, Event::End) {
                    return Ok(());
                }
                let Event::Unsigned(key) = event else {
                    return Err(Status::UnexpectedType);
                };
                if self.previous.is_some_and(|old| key <= old) {
                    return Err(Status::InvalidCbor);
                }
                self.previous = Some(key);
                self.key = Some(key);
                return Ok(());
            };
            self.entity = 0;
            match (key, event) {
                (1, Event::Bytes(32)) => p.spans[0] = span(32),
                (1, Event::Bytes(_)) => return Err(Status::InvalidLength),
                (2 | 3, Event::Map(_)) => {
                    self.entity = key as u8;
                    self.previous_text = Span::NONE;
                    self.value = false;
                }
                (0x80, Event::Bool(value)) => p.metadata_only = value,
                (1..=3 | 0x80, _) => return Err(Status::UnexpectedType),
                _ => (),
            }
        } else if self.entity != 0 && depth == 2 {
            if self.value {
                self.value = false;
                match (self.entity, self.member, event) {
                    (2, 1, Event::Bytes(n)) => {
                        if usize::from(n) != core::mem::size_of::<credential::Id>() {
                            return Err(Status::NoCredentials);
                        }
                        p.spans[1] = span(n);
                    }
                    (2, 2, Event::Text(n)) => {
                        self.text = span(n);
                        self.text_kind = 2;
                    }
                    (3, 1, Event::Bytes(n @ 1..=64)) => p.spans[2] = span(n),
                    (3, 1, Event::Bytes(_)) => return Err(Status::InvalidLength),
                    (3, m @ (3 | 4), Event::Text(n)) => p.spans[usize::from(m)] = span(n),
                    (_, 0, _) => (),
                    _ => return Err(Status::UnexpectedType),
                }
            } else {
                match event {
                    Event::Text(n) => {
                        self.text = span(n);
                        self.text_kind = 1;
                    }
                    Event::End => {
                        if (self.entity == 2 && (!self.public_key || p.spans[1].start == 0))
                            || (self.entity == 3 && p.spans[2].start == 0)
                        {
                            return Err(Status::MissingParameter);
                        }
                        self.entity = 0;
                    }
                    _ => return Err(Status::UnexpectedType),
                }
            }
        } else if depth == 3 && matches!(event, Event::End) && self.text_kind != 0 {
            let text = self.text.bytes(raw);
            if self.text_kind == 1 {
                let old = self.previous_text;
                if old.start != 0 && (self.text.len, text) <= (old.len, old.bytes(raw)) {
                    return Err(Status::InvalidCbor);
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::applets::ctap::{Command, envelope};
    use std::{vec, vec::Vec};

    fn check(params: &[u8]) {
        let expected = super::super::parse(params);
        let mut message = vec![0xa2, 1, 7, 2];
        message.extend_from_slice(params);
        for split in 0..=message.len() {
            let mut parser = envelope::Parser::new(0x0a);
            parser.consume(&message[..split]);
            parser.consume(&message[split..]);
            let Ok(Command::Management(p)) = parser.finish() else {
                panic!("envelope rejected {message:?}");
            };
            assert_eq!(&p.message[envelope::PREFIX..p.len], params);
            assert_eq!(
                p.management.fields(&p.message),
                expected,
                "split={split} params={params:?}"
            );
        }
    }
    fn bytes(length: usize) -> Vec<u8> {
        let mut v = if length < 24 {
            vec![0x40 + length as u8]
        } else {
            vec![0x58, length as u8]
        };
        v.resize(v.len() + length, 0x42);
        v
    }
    #[test]
    fn semantic_offsets_match_slice_oracle_at_every_fragment_boundary() {
        let mut values = vec![
            vec![0],
            vec![0xf5],
            vec![0x60],
            vec![0x61, b'x'],
            vec![0xa0],
            vec![0x80],
        ];
        for n in [0, 1, 31, 32, 64, 65, core::mem::size_of::<credential::Id>()] {
            values.push(bytes(n));
        }
        for key in [
            vec![1],
            vec![2],
            vec![3],
            vec![0x18, 0x80],
            vec![0x20],
            vec![0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ] {
            for value in &values {
                let mut p = vec![0xa1];
                p.extend_from_slice(&key);
                p.extend_from_slice(value);
                check(&p);
            }
        }
        for entity in [2, 3] {
            for field in [
                "id",
                "type",
                "name",
                "displayName",
                "longUnknownFieldNameWithUnicode界",
            ] {
                for value in &values {
                    let mut p = vec![0xa1, entity, 0xa1];
                    if field.len() < 24 {
                        p.push(0x60 + field.len() as u8);
                    } else {
                        p.extend_from_slice(&[0x78, field.len() as u8]);
                    }
                    p.extend_from_slice(field.as_bytes());
                    p.extend_from_slice(value);
                    check(&p);
                }
            }
        }
        let mut p = vec![0xa4, 1];
        p.extend(bytes(32));
        p.extend_from_slice(&[2, 0xa2, 0x62, b'i', b'd']);
        p.extend(bytes(core::mem::size_of::<credential::Id>()));
        p.extend_from_slice(b"\x64type\x6apublic-key");
        p.extend_from_slice(
            b"\x03\xa3\x62id\x41x\x64name\x63\xe7\x95\x8c\x6bdisplayName\x60\x18\x80\xf5",
        );
        check(&p);
        for p in [
            b"\xa2\x01\x40\x01\x40".as_slice(),
            b"\xa1\x03\xa2\x64name\x60\x62id\x41x",
            b"\xa1\x03\xa2\x62id\x41x\x62id\x41y",
        ] {
            check(p);
        }
    }
    #[test]
    fn envelope_errors_precede_deferred_management_errors() {
        // Bad credential ID length precedes a later invalid protocol in the
        // bytes, but management semantics historically ran after the envelope.
        for (message, expected) in [
            (
                &b"\xa3\x01\x07\x02\xa1\x02\xa1\x62id\x40\x03\x00"[..],
                Status::InvalidParameter,
            ),
            (
                &b"\xa3\x01\x07\x02\xa1\x02\xa1\x62id\x40\x03"[..],
                Status::InvalidCbor,
            ),
            (
                &b"\xa1\x02\xa1\x02\xa1\x62id\x40"[..],
                Status::MissingParameter,
            ),
        ] {
            let mut parser = envelope::Parser::new(0x0a);
            for byte in message {
                parser.consume(core::slice::from_ref(byte));
            }
            assert!(matches!(parser.finish(), Err(error) if error == expected));
        }
    }
}
