// SPDX-License-Identifier: Apache-2.0
//! Streaming makeCredential/getAssertion schema; no transport-backed fields.
use super::{
    Command, Key, Status,
    credential::{ID_BYTES, Id},
};
use canokey_protocol::cbor::Event;
pub const CRED_BLOB_BYTES: usize = 32;

pub(super) const MAX_LIST: usize = 16;
pub struct Parameters {
    pub make: bool,
    pub client_hash: [u8; 32],
    pub rp: [u8; 254],
    pub rp_len: usize,
    pub user: [u8; 64],
    pub user_len: usize,
    pub name: [u8; 64],
    pub name_len: usize,
    pub display: [u8; 64],
    pub display_len: usize,
    pub list_present: bool,
    pub algorithm: Option<u8>,
    pub algorithms: [i32; super::MAX_REQUEST / 20],
    pub algorithm_count: usize,
    pub list: [Id; MAX_LIST],
    pub list_len: usize,
    pub resident: bool,
    pub up: bool,
    pub uv: bool,
    pub auth: [u8; 32],
    pub auth_len: Option<usize>,
    pub protocol: u8,
    pub protection: u8,
    pub protection_requested: bool,
    pub min_pin_length: bool,
    pub large_blob_key: bool,
    pub cred_blob: [u8; CRED_BLOB_BYTES],
    pub cred_blob_len: Option<usize>,
    pub get_cred_blob: bool,
    pub hmac_secret: bool,
    pub third_party_payment: bool,
    pub hmac: Option<super::hmac_secret::Parameters>,
}
impl Parameters {
    const fn new(make: bool) -> Self {
        Self {
            make,
            client_hash: [0; 32],
            rp: [0; 254],
            rp_len: 0,
            user: [0; 64],
            user_len: 0,
            name: [0; 64],
            name_len: 0,
            display: [0; 64],
            display_len: 0,
            list_present: false,
            algorithm: None,
            algorithms: [0; super::MAX_REQUEST / 20],
            algorithm_count: 0,
            list: [[0; ID_BYTES]; MAX_LIST],
            list_len: 0,
            resident: false,
            up: true,
            uv: false,
            auth: [0; 32],
            auth_len: None,
            protocol: 0,
            protection: 1,
            protection_requested: false,
            min_pin_length: false,
            large_blob_key: false,
            cred_blob: [0; CRED_BLOB_BYTES],
            cred_blob_len: None,
            get_cred_blob: false,
            hmac_secret: false,
            third_party_payment: false,
            hmac: None,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Root,
    Rp,
    User,
    Algorithms,
    Algorithm,
    List,
    Descriptor,
    Options,
    Extensions,
}
#[derive(Clone, Copy)]
enum Field {
    Ignore,
    ClientHash,
    Rp,
    User,
    UserId,
    Name,
    Display,
    Algorithms,
    Algorithm,
    List,
    DescriptorId,
    Type,
    Options,
    Resident,
    Up,
    Uv,
    Auth,
    Protocol,
    Extensions,
    Protection,
    MinPinLength,
    LargeBlobKey,
    CredBlob,
    ThirdPartyPayment,
    HmacSecret,
    HmacSecretMc,
    Enterprise,
}
// Each entry is (context, wire key, destination, makeCredential only).
// Keep schema matching data-driven rather than expanding a string match tree.
fn text_field(context: Context, key: &[u8], make: bool) -> Field {
    const FIELDS: &[(Context, &[u8], Field, bool)] = &[
        (Context::Rp, b"id", Field::Rp, false),
        (Context::User, b"id", Field::UserId, false),
        (Context::User, b"name", Field::Name, false),
        (Context::User, b"displayName", Field::Display, false),
        (Context::Algorithm, b"alg", Field::Algorithm, false),
        (Context::Algorithm, b"type", Field::Type, false),
        (Context::Descriptor, b"type", Field::Type, false),
        (Context::Descriptor, b"id", Field::DescriptorId, false),
        (Context::Options, b"rk", Field::Resident, false),
        (Context::Options, b"uv", Field::Uv, false),
        (Context::Options, b"up", Field::Up, false),
        (
            Context::Extensions,
            b"thirdPartyPayment",
            Field::ThirdPartyPayment,
            false,
        ),
        (
            Context::Extensions,
            b"hmac-secret",
            Field::HmacSecret,
            false,
        ),
        (
            Context::Extensions,
            b"hmac-secret-mc",
            Field::HmacSecretMc,
            true,
        ),
        (Context::Extensions, b"credBlob", Field::CredBlob, false),
        (
            Context::Extensions,
            b"largeBlobKey",
            Field::LargeBlobKey,
            true,
        ),
        (
            Context::Extensions,
            b"minPinLength",
            Field::MinPinLength,
            true,
        ),
        (Context::Extensions, b"credProtect", Field::Protection, true),
    ];
    FIELDS
        .iter()
        .find(|(scope, name, _, make_only)| {
            *scope == context && *name == key && (!make_only || make)
        })
        .map_or(Field::Ignore, |(_, _, field, _)| *field)
}

struct Map {
    context: Context,
    previous_int: Option<Key>,
    previous_text: [u8; 32],
    previous_len: usize,
    seen_text: bool,
    field: Option<Field>,
}
impl Map {
    const fn new(context: Context) -> Self {
        Self {
            context,
            previous_int: None,
            previous_text: [0; 32],
            previous_len: 0,
            seen_text: false,
            field: None,
        }
    }
}
struct Fields {
    params: Parameters,
    maps: [Map; 3],
    level: usize,
    started: bool,
    seen: u8,
    body: Option<(Field, usize)>,
    key_body: bool,
    key: [u8; 32],
    key_len: usize,
    skip: u8,
    item_type: bool,
    item_type_seen: bool,
    item_algorithm_seen: bool,
    item_id: bool,
    item_algorithm: Option<i32>,
    item_id_valid: bool,
    hmac: super::hmac_secret::Parser,
    in_hmac: bool,
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
}
impl Parser {
    pub const fn new(make: bool) -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::new(),
            fields: Fields {
                params: Parameters::new(make),
                maps: [
                    Map::new(Context::Root),
                    Map::new(Context::Root),
                    Map::new(Context::Root),
                ],
                level: 0,
                started: false,
                seen: 0,
                body: None,
                key_body: false,
                key: [0; 32],
                key_len: 0,
                skip: 0,
                item_type: false,
                item_type_seen: false,
                item_algorithm_seen: false,
                item_id: false,
                item_algorithm: None,
                item_id_valid: false,
                hmac: super::hmac_secret::Parser::new(),
                in_hmac: false,
            },
        }
    }
    // Share this parser across HID and APDU callers on size-constrained targets.
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let fields = &mut self.fields;
        self.decoder
            .consume(bytes, &mut |event, _| fields.event(event));
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        let p = &mut self.fields.params;
        memory.wipe(&mut p.client_hash);
        memory.wipe(&mut p.rp);
        memory.wipe(&mut p.user);
        memory.wipe(&mut p.name);
        memory.wipe(&mut p.display);
        memory.wipe(&mut p.auth);
        memory.wipe(&mut p.cred_blob);
        for id in &mut p.list {
            memory.wipe(id);
        }
        if let Some(hmac) = &mut p.hmac {
            hmac.clear(memory);
        }
        memory.wipe(&mut self.fields.key);
        for map in &mut self.fields.maps {
            memory.wipe(&mut map.previous_text);
        }
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let f = &mut self.fields;
        f.params.name_len = super::resident::text_prefix(&f.params.name[..f.params.name_len]).len();
        f.params.display_len =
            super::resident::text_prefix(&f.params.display[..f.params.display_len]).len();
        let required = if f.params.make { 15 } else { 3 };
        if f.seen & required != required {
            return Err(Status::MissingParameter);
        }
        if f.params.make && f.params.algorithm_count == 0 {
            return Err(Status::UnsupportedAlgorithm);
        }
        if f.params.auth_len.is_some() && f.params.protocol == 0 {
            return Err(Status::MissingParameter);
        }
        if f.params
            .auth_len
            .is_some_and(|n| n != 0 && n != if f.params.protocol == 1 { 16 } else { 32 })
        {
            return Err(Status::InvalidParameter);
        }
        if f.params.make && f.params.hmac.is_some() && !f.params.hmac_secret {
            return Err(Status::InvalidOption);
        }
        Ok(Command::Credential(core::mem::replace(
            &mut f.params,
            Parameters::new(false),
        )))
    }
}
impl Fields {
    #[inline(never)]
    fn event(&mut self, event: Event<'_>) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if self.in_hmac {
            if self.hmac.event(event)? {
                self.in_hmac = false;
                self.params.hmac = Some(
                    core::mem::replace(&mut self.hmac, super::hmac_secret::Parser::new()).params,
                );
            }
            return Ok(());
        }
        if self.skip != 0 {
            match event {
                Event::Map(_) | Event::Array(_) | Event::Bytes(_) | Event::Text(_) => {
                    self.skip += 1
                }
                Event::End => self.skip -= 1,
                _ => (),
            }
            return Ok(());
        }
        if let Some((field, pos)) = self.body {
            match event {
                Event::Data(bytes) => {
                    let out: &mut [u8] = if self.key_body {
                        &mut self.key
                    } else {
                        match field {
                            Field::ClientHash => &mut self.params.client_hash,
                            Field::Rp => &mut self.params.rp,
                            Field::UserId => &mut self.params.user,
                            Field::Name => &mut self.params.name,
                            Field::Display => &mut self.params.display,
                            Field::Auth => &mut self.params.auth,
                            Field::CredBlob => &mut self.params.cred_blob,
                            Field::DescriptorId => &mut self.params.list[self.params.list_len],
                            Field::Type => &mut self.key,
                            _ => return Err(Status::InvalidCbor),
                        }
                    };
                    let copied = bytes.len().min(out.len().saturating_sub(pos));
                    if copied != 0 {
                        out[pos..pos + copied].copy_from_slice(&bytes[..copied]);
                    }
                    self.body = Some((field, pos + bytes.len()));
                }
                Event::End => {
                    if matches!(field, Field::CredBlob) && self.params.cred_blob_len != Some(pos) {
                        return Err(Status::InvalidCbor);
                    }
                    self.body = None;
                    if self.key_body {
                        self.key_body = false;
                        self.text_key()?;
                    } else if matches!(field, Field::Type) {
                        self.item_type = pos == 10 && &self.key[..pos] == b"public-key";
                    }
                }
                _ => return Err(Status::InvalidCbor),
            }
            return Ok(());
        }
        let context = self.maps[self.level].context;
        if matches!(event, Event::End) {
            if matches!(context, Context::Algorithm | Context::Descriptor)
                && (!self.item_type_seen
                    || (context == Context::Algorithm && !self.item_algorithm_seen))
            {
                return Err(Status::MissingParameter);
            }
            if context == Context::Algorithm && self.item_type {
                if let Some(algorithm) = self.item_algorithm {
                    // Each complete public-key descriptor costs over 20 wire bytes,
                    // so this cannot fill before the overall request limit.
                    let slot = self
                        .params
                        .algorithms
                        .get_mut(self.params.algorithm_count)
                        .ok_or(Status::LimitExceeded)?;
                    *slot = algorithm;
                    self.params.algorithm_count += 1;
                }
            }
            if context == Context::Descriptor {
                if !self.item_id {
                    return Err(Status::MissingParameter);
                }
                if self.item_type && self.item_id_valid {
                    self.params.list_len += 1;
                }
            }
            if self.level != 0 {
                self.level -= 1;
            }
            return Ok(());
        }
        if context == Context::Algorithms || context == Context::List {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.item_type = false;
            self.item_type_seen = false;
            self.item_algorithm_seen = false;
            self.item_id = false;
            self.item_id_valid = false;
            self.item_algorithm = None;
            self.push(if context == Context::Algorithms {
                Context::Algorithm
            } else {
                Context::Descriptor
            });
            return Ok(());
        }
        if let Some(field) = self.maps[self.level].field.take() {
            return self.value(field, event);
        }
        if context == Context::Root {
            let map = &mut self.maps[self.level];
            let key = Key::ordered(event, &mut map.previous_int)?;
            map.field = Some(if self.params.make {
                match key {
                    Some(1) => Field::ClientHash,
                    Some(2) => Field::Rp,
                    Some(3) => Field::User,
                    Some(4) => Field::Algorithms,
                    Some(5) => Field::List,
                    Some(6) => Field::Extensions,
                    Some(7) => Field::Options,
                    Some(8) => Field::Auth,
                    Some(9) => Field::Protocol,
                    Some(10) => Field::Enterprise,
                    _ => Field::Ignore,
                }
            } else {
                match key {
                    Some(1) => Field::Rp,
                    Some(2) => Field::ClientHash,
                    Some(3) => Field::List,
                    Some(4) => Field::Extensions,
                    Some(5) => Field::Options,
                    Some(6) => Field::Auth,
                    Some(7) => Field::Protocol,
                    _ => Field::Ignore,
                }
            });
        } else {
            match event {
                Event::Text(n) if n <= 32 => {
                    self.key_len = usize::from(n);
                    self.key_body = true;
                    self.body = Some((Field::Ignore, 0));
                }
                Event::Text(_) => return Err(Status::InvalidCbor),
                _ => return Err(Status::UnexpectedType),
            }
        }
        Ok(())
    }
    #[inline(never)]
    fn text_key(&mut self) -> Result<(), Status> {
        let key = &self.key[..self.key_len];
        let map = &mut self.maps[self.level];
        if map.seen_text
            && (self.key_len, key) <= (map.previous_len, &map.previous_text[..map.previous_len])
        {
            return Err(Status::InvalidCbor);
        }
        map.previous_len = self.key_len;
        map.previous_text[..self.key_len].copy_from_slice(key);
        map.seen_text = true;
        map.field = Some(text_field(map.context, key, self.params.make));
        Ok(())
    }
    fn push(&mut self, context: Context) {
        self.level += 1;
        self.maps[self.level] = Map::new(context);
    }
    fn value(&mut self, field: Field, event: Event<'_>) -> Result<(), Status> {
        match field {
            Field::ClientHash => {
                self.bytes(field, event, 32, 32)?;
                self.seen |= 1;
            }
            Field::Rp => {
                if self.params.make && self.level == 0 {
                    if !matches!(event, Event::Map(_)) {
                        return Err(Status::UnexpectedType);
                    }
                    self.push(Context::Rp);
                } else {
                    match event {
                        Event::Text(n) if n > 0 && n <= 254 => {
                            self.params.rp_len = n as usize;
                            self.body = Some((field, 0));
                            self.seen |= 2;
                        }
                        Event::Text(_) => return Err(Status::InvalidLength),
                        _ => return Err(Status::UnexpectedType),
                    }
                }
            }
            Field::User | Field::Options | Field::Extensions => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.push(match field {
                    Field::User => Context::User,
                    Field::Options => Context::Options,
                    _ => Context::Extensions,
                });
            }
            Field::Name | Field::Display => {
                let Event::Text(n) = event else {
                    return Err(Status::UnexpectedType);
                };
                if matches!(field, Field::Name) {
                    self.params.name_len = usize::from(n).min(64);
                } else {
                    self.params.display_len = usize::from(n).min(64);
                }
                self.body = Some((field, 0));
            }
            Field::UserId => {
                let n = self.bytes(field, event, 1, 64)?;
                self.params.user_len = n;
                self.seen |= 4;
            }
            Field::Algorithms | Field::List => {
                let Event::Array(n) = event else {
                    return Err(Status::UnexpectedType);
                };
                if matches!(field, Field::List) && n as usize > MAX_LIST {
                    return Err(Status::LimitExceeded);
                }
                if matches!(field, Field::List) {
                    self.params.list_present = true;
                }
                let context = if matches!(field, Field::Algorithms) {
                    self.seen |= 8;
                    Context::Algorithms
                } else {
                    Context::List
                };
                self.push(context);
            }
            Field::Algorithm => {
                self.item_algorithm_seen = true;
                let key = Key::parse(event)?;
                self.item_algorithm = i32::try_from(key.argument)
                    .ok()
                    .map(|n| if key.negative { -1 - n } else { n });
            }
            Field::DescriptorId => {
                let Event::Bytes(n) = event else {
                    return Err(Status::UnexpectedType);
                };
                self.item_id = true;
                self.item_id_valid = n as usize == ID_BYTES;
                if self.item_id_valid {
                    self.body = Some((field, 0));
                } else {
                    self.skip = 1;
                }
            }
            Field::Type => {
                self.item_type_seen = true;
                let Event::Text(n) = event else {
                    return Err(Status::UnexpectedType);
                };
                if n == 10 {
                    self.body = Some((field, 0));
                } else {
                    self.skip = 1;
                }
            }
            Field::Resident | Field::Uv | Field::Up | Field::MinPinLength | Field::LargeBlobKey => {
                let Event::Bool(value) = event else {
                    return Err(Status::UnexpectedType);
                };
                match field {
                    Field::Resident => self.params.resident = value,
                    Field::Uv => self.params.uv = value,
                    Field::LargeBlobKey => self.params.large_blob_key = value,
                    Field::MinPinLength => self.params.min_pin_length = value,
                    _ => self.params.up = value,
                }
            }
            Field::Auth => {
                let n = self.bytes(field, event, 0, 32)?;
                self.params.auth_len = Some(n);
            }
            Field::Protocol => match event {
                Event::Unsigned(n @ (1 | 2)) => self.params.protocol = n as u8,
                _ => return Err(Status::InvalidParameter),
            },
            Field::Protection => match event {
                Event::Unsigned(n @ 1..=3) => {
                    self.params.protection = n as u8;
                    self.params.protection_requested = true;
                }
                _ => return Err(Status::InvalidParameter),
            },
            Field::CredBlob => {
                if self.params.make {
                    let Event::Bytes(n) = event else {
                        return Err(Status::UnexpectedType);
                    };
                    // Consume the entire byte string, retaining only the bounded
                    // prefix. Oversized blobs produce credBlob=false, not a
                    // makeCredential error, and must never be persisted truncated.
                    self.params.cred_blob_len = Some(usize::from(n));
                    self.body = Some((field, 0));
                } else {
                    let Event::Bool(value) = event else {
                        return Err(Status::UnexpectedType);
                    };
                    self.params.get_cred_blob = value;
                }
            }
            Field::ThirdPartyPayment => {
                let Event::Bool(value) = event else {
                    return Err(Status::UnexpectedType);
                };
                if self.params.make && !value {
                    return Err(Status::InvalidOption);
                }
                self.params.third_party_payment = value;
            }
            Field::HmacSecret if self.params.make => {
                let Event::Bool(value) = event else {
                    return Err(Status::UnexpectedType);
                };
                self.params.hmac_secret = value;
            }
            Field::HmacSecret | Field::HmacSecretMc => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.in_hmac = true;
            }
            Field::Enterprise => return Err(Status::InvalidParameter),
            Field::Ignore => {
                if matches!(
                    event,
                    Event::Map(_) | Event::Array(_) | Event::Bytes(_) | Event::Text(_)
                ) {
                    self.skip = 1;
                }
            }
        }
        Ok(())
    }
    #[inline(never)]
    fn bytes(
        &mut self,
        field: Field,
        event: Event<'_>,
        min: u16,
        max: u16,
    ) -> Result<usize, Status> {
        let Event::Bytes(n) = event else {
            return Err(Status::UnexpectedType);
        };
        if n < min || n > max {
            return Err(Status::InvalidLength);
        }
        self.body = Some((field, 0));
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey_protocol::cbor::Encoder;

    #[test]
    fn table_preserves_field_scope_and_make_only_extensions() {
        fn reference(context: Context, key: &[u8], make: bool) -> Field {
            match (context, key) {
                (Context::Rp, b"id") => Field::Rp,
                (Context::User, b"id") => Field::UserId,
                (Context::User, b"name") => Field::Name,
                (Context::User, b"displayName") => Field::Display,
                (Context::Algorithm, b"alg") => Field::Algorithm,
                (Context::Algorithm | Context::Descriptor, b"type") => Field::Type,
                (Context::Descriptor, b"id") => Field::DescriptorId,
                (Context::Options, b"rk") => Field::Resident,
                (Context::Options, b"uv") => Field::Uv,
                (Context::Options, b"up") => Field::Up,
                (Context::Extensions, b"thirdPartyPayment") => Field::ThirdPartyPayment,
                (Context::Extensions, b"hmac-secret") => Field::HmacSecret,
                (Context::Extensions, b"hmac-secret-mc") if make => Field::HmacSecretMc,
                (Context::Extensions, b"credBlob") => Field::CredBlob,
                (Context::Extensions, b"largeBlobKey") if make => Field::LargeBlobKey,
                (Context::Extensions, b"minPinLength") if make => Field::MinPinLength,
                (Context::Extensions, b"credProtect") if make => Field::Protection,
                _ => Field::Ignore,
            }
        }
        let keys: &[&[u8]] = &[
            b"id",
            b"name",
            b"displayName",
            b"alg",
            b"type",
            b"rk",
            b"uv",
            b"up",
            b"thirdPartyPayment",
            b"hmac-secret",
            b"hmac-secret-mc",
            b"credBlob",
            b"largeBlobKey",
            b"minPinLength",
            b"credProtect",
            b"",
            b"unknown",
        ];
        for context in [
            Context::Root,
            Context::Rp,
            Context::User,
            Context::Algorithms,
            Context::Algorithm,
            Context::List,
            Context::Descriptor,
            Context::Options,
            Context::Extensions,
        ] {
            for make in [false, true] {
                for key in keys {
                    for length in 0..=key.len() {
                        let key = &key[..length];
                        assert_eq!(
                            text_field(context, key, make) as u8,
                            reference(context, key, make) as u8
                        );
                        for position in 0..key.len() {
                            let mut changed = key.to_vec();
                            changed[position] ^= 0x20;
                            assert_eq!(
                                text_field(context, &changed, make) as u8,
                                reference(context, &changed, make) as u8
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn cred_blob_consumes_oversized_values_without_growing_storage() {
        let value = [0x5a; 512];
        for length in [0, 31, 32, 33, 255, 256, 512] {
            let mut bytes = [0; 1024];
            let mut e = Encoder::new(&mut bytes[..]);
            e.map(6)
                .u8(1)
                .bytes(&[1; 32])
                .u8(2)
                .map(1)
                .str("id")
                .str("example.com")
                .u8(3)
                .map(1)
                .str("id")
                .bytes(b"user")
                .u8(4)
                .array(1)
                .map(2)
                .str("alg")
                .i8(-7)
                .str("type")
                .str("public-key")
                .u8(6)
                .map(1)
                .str("credBlob")
                .bytes(&value[..length])
                .u8(7)
                .map(1)
                .str("rk")
                .bool(true)
                .finish()
                .unwrap();
            let n = 1024 - e.writer().len();
            for split in 0..=n {
                let mut parser = Parser::new(true);
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..n]);
                let Ok(Command::Credential(p)) = parser.finish() else {
                    panic!("length {length}, split {split}");
                };
                assert_eq!(p.cred_blob_len, Some(length));
                let retained = length.min(CRED_BLOB_BYTES);
                assert_eq!(&p.cred_blob[..retained], &value[..retained]);
                assert!(p.resident, "the field after the blob must be decoded");
            }
            for truncated in 0..n {
                let mut parser = Parser::new(true);
                parser.consume(&bytes[..truncated]);
                assert!(parser.finish().is_err());
            }
        }
    }

    #[test]
    fn hmac_extension_survives_every_input_split() {
        for protocol in [1, 2] {
            let mut bytes = [0; 384];
            let mut e = Encoder::new(&mut bytes[..]);
            e.map(3)
                .u8(1)
                .str("example.com")
                .u8(2)
                .bytes(&[1; 32])
                .u8(4)
                .map(1)
                .str("hmac-secret")
                .map(if protocol == 1 { 3 } else { 4 })
                .u8(1)
                .map(5)
                .u8(1)
                .u8(2)
                .u8(3)
                .i8(-25)
                .i8(-1)
                .u8(1)
                .i8(-2)
                .bytes(&[2; 32])
                .i8(-3)
                .bytes(&[3; 32])
                .u8(2)
                .bytes(&[4; 80][..if protocol == 1 { 64 } else { 80 }])
                .u8(3)
                .bytes(&[5; 32][..if protocol == 1 { 16 } else { 32 }])
                .finish()
                .unwrap();
            if protocol == 2 {
                e.u8(4).u8(2).finish().unwrap();
            }
            let n = 384 - e.writer().len();
            for split in 0..=n {
                let mut parser = Parser::new(false);
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..n]);
                assert!(matches!(parser.finish(), Ok(Command::Credential(p)) if p.hmac.is_some()));
            }
        }
    }
}
