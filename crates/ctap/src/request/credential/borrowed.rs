// SPDX-License-Identifier: Apache-2.0
//! Borrowed credential schema. The reader and extension/algorithm profile keep
//! product admission and error identity; slices borrow the caller's input only.
use super::{
    CLIENT_DATA_HASH_BYTES, RP_ID_MAX,
    schema::{self, Field},
};
use crate::request::{
    Error,
    stream::{Key, TextOrder},
};

pub trait Reader<'a>: Sized {
    type Error: Error;
    fn new(bytes: &'a [u8]) -> Self;
    fn validate(bytes: &'a [u8]) -> Result<(), Self::Error>;
    fn done(&self) -> bool;
    fn remaining(&self) -> &'a [u8];
    fn map(&mut self) -> Result<usize, Self::Error>;
    fn array(&mut self) -> Result<usize, Self::Error>;
    fn uint(&mut self) -> Result<u64, Self::Error>;
    fn parameter_uint(&mut self) -> Result<u64, Self::Error> {
        self.uint()
    }
    fn int(&mut self) -> Result<i64, Self::Error>;
    fn boolean(&mut self) -> Result<bool, Self::Error>;
    fn text(&mut self) -> Result<&'a str, Self::Error>;
    fn bytes(&mut self) -> Result<&'a [u8], Self::Error>;
    /// Admit a wire length before requiring its complete body. Streaming CTAP
    /// reports a field length error even when that rejected body is truncated.
    fn bytes_checked(
        &mut self,
        admit: impl FnOnce(usize) -> Result<(), Self::Error>,
    ) -> Result<&'a [u8], Self::Error> {
        let bytes = self.bytes()?;
        admit(bytes.len())?;
        Ok(bytes)
    }
    fn text_checked(
        &mut self,
        admit: impl FnOnce(usize) -> Result<(), Self::Error>,
    ) -> Result<&'a str, Self::Error> {
        let text = self.text()?;
        admit(text.len())?;
        Ok(text)
    }
    fn integer(&mut self) -> Result<(bool, u64), Self::Error> {
        let mut bytes = self.item()?;
        let limit = u16::try_from(bytes.len()).map_err(|_| Self::Error::INVALID_CBOR)?;
        match canokey_protocol::cbor::Decoder::new(limit)
            .next_event(&mut bytes)
            .map_err(|_| Self::Error::INVALID_CBOR)?
        {
            Some(canokey_protocol::cbor::Event::Unsigned(value)) => Ok((false, value)),
            Some(canokey_protocol::cbor::Event::Negative(value)) => Ok((true, value)),
            _ => Err(Self::Error::UNEXPECTED_TYPE),
        }
    }
    fn item(&mut self) -> Result<&'a [u8], Self::Error>;
    fn skip_unknown(&mut self) -> Result<(), Self::Error> {
        self.item().map(|_| ())
    }
}

pub trait Profile<'a> {
    type Reader: Reader<'a>;
    type Extensions: Default;
    type Algorithm;
    fn extensions(
        reader: &mut Self::Reader,
        make: bool,
    ) -> Result<Self::Extensions, ParseError<'a, Self>>;
    fn algorithm(kind: &str, algorithm: i64, vcap: bool) -> Option<Self::Algorithm>;
}
type ParseError<'a, P> = <<P as Profile<'a>>::Reader as Reader<'a>>::Error;
#[derive(Clone, Copy, Default)]
pub struct Options {
    pub rk: bool,
    pub up: Option<bool>,
    pub uv: bool,
}
impl Options {
    fn read<'a, R: Reader<'a>>(r: &mut R, make: bool) -> Result<Self, R::Error> {
        let mut options = Self::default();
        let mut order = TextOrder::new();
        for _ in 0..r.map()? {
            let key = order.next(r)?;
            let field = schema::text_field(schema::Context::Options, key.as_bytes(), make);
            // CanoKey requires a boolean for every option, including unknown
            // names. Command-only options reject after this type admission.
            let value = r.boolean()?;
            schema::admit_option::<R::Error>(make, field)?;
            match field {
                Field::Resident => options.rk = value,
                Field::Up => options.up = Some(value),
                Field::Uv => options.uv = value,
                _ => {}
            }
        }
        Ok(options)
    }
}
pub struct Request<'a, P: Profile<'a>> {
    pub client_hash: &'a [u8; CLIENT_DATA_HASH_BYTES],
    pub rp: &'a str,
    pub user_id: Option<&'a [u8]>,
    pub user_name: Option<&'a str>,
    pub user_display: Option<&'a str>,
    pub extensions: P::Extensions,
    pub algorithms: Option<&'a [u8]>,
    pub list: Option<&'a [u8]>,
    pub options: Options,
    pub auth: Option<&'a [u8]>,
    pub protocol: Option<u64>,
}
struct Entity<'a> {
    id: Option<&'a [u8]>,
    name: Option<&'a str>,
    display: Option<&'a str>,
}
fn entity<'a, R: Reader<'a>>(r: &mut R, user: bool) -> Result<Entity<'a>, R::Error> {
    let mut entity = Entity {
        id: None,
        name: None,
        display: None,
    };
    let context = if user {
        schema::Context::User
    } else {
        schema::Context::Rp
    };
    let mut order = TextOrder::new();
    for _ in 0..r.map()? {
        let key = order.next(r)?;
        match schema::text_field(context, key.as_bytes(), true) {
            Field::Rp => {
                let value = r
                    .text_checked(|length| admit_length::<R::Error>(length, 1, RP_ID_MAX))?
                    .as_bytes();
                entity.id = Some(value);
            }
            Field::UserId => {
                let value = r.bytes_checked(|length| {
                    admit_length::<R::Error>(length, 1, crate::resident::USER_ID_BYTES)
                })?;
                entity.id = Some(value);
            }
            Field::TextOnly => {
                r.text()?;
            }
            Field::Name => entity.name = Some(r.text()?),
            Field::Display => entity.display = Some(r.text()?),
            _ => {
                r.skip_unknown()?;
            }
        }
    }
    Ok(entity)
}
fn algorithm_entry<'a, R: Reader<'a>>(reader: &mut R) -> Result<(&'a str, Option<i32>), R::Error> {
    let (mut kind, mut algorithm, mut seen_algorithm) = (None, None, false);
    let mut order = TextOrder::new();
    for _ in 0..reader.map()? {
        match order.next(reader)? {
            "alg" => {
                algorithm = Key::<R::Error>::borrowed_i32(reader)?;
                seen_algorithm = true;
            }
            "type" => kind = Some(reader.text()?),
            _ => reader.skip_unknown()?,
        }
    }
    if !seen_algorithm {
        return Err(R::Error::MISSING_PARAMETER);
    }
    Ok((kind.ok_or(R::Error::MISSING_PARAMETER)?, algorithm))
}
impl<'a, P: Profile<'a>> Request<'a, P> {
    #[inline(never)]
    pub fn decode(bytes: &'a [u8], make: bool) -> Result<Self, ParseError<'a, P>> {
        let mut r = P::Reader::new(bytes);
        let (mut hash, mut rp, mut user, mut algorithms, mut list, mut auth, mut protocol) =
            (None, None, None, None, None, None, None);
        let mut options = Options::default();
        let (mut user_name, mut user_display) = (None, None);
        let mut extensions = P::Extensions::default();
        let mut previous = None;
        let mut algorithm_count = 0;
        for _ in 0..r.map()? {
            let key = Key::<ParseError<'a, P>>::borrowed_ordered(&mut r, &mut previous)?;
            match schema::root_field(key, make) {
                Field::ClientHash => {
                    let value = r.bytes_checked(|length| {
                        admit_length::<ParseError<'a, P>>(
                            length,
                            CLIENT_DATA_HASH_BYTES,
                            CLIENT_DATA_HASH_BYTES,
                        )
                    })?;
                    hash = Some(
                        value
                            .try_into()
                            .map_err(|_| ParseError::<'a, P>::INVALID_LENGTH)?,
                    );
                }
                Field::Rp if make => {
                    rp = entity(&mut r, false)?
                        .id
                        .map(|id| {
                            core::str::from_utf8(id).map_err(|_| ParseError::<'a, P>::INVALID_CBOR)
                        })
                        .transpose()?;
                }
                Field::Rp => {
                    let value = r.text_checked(|length| {
                        admit_length::<ParseError<'a, P>>(length, 1, RP_ID_MAX)
                    })?;
                    rp = Some(value);
                }
                Field::User => {
                    let entity = entity(&mut r, true)?;
                    user = entity.id;
                    user_name = entity.name;
                    user_display = entity.display;
                }
                Field::Algorithms => {
                    let before = r.remaining();
                    for _ in 0..r.array()? {
                        let (kind, algorithm) = algorithm_entry(&mut r)?;
                        if kind == "public-key" && algorithm.is_some() {
                            algorithm_count += 1;
                        }
                    }
                    algorithms = Some(&before[..before.len() - r.remaining().len()]);
                }
                Field::List => {
                    let before = r.remaining();
                    let count = r.array()?;
                    if count > super::MAX_LIST {
                        return Err(ParseError::<'a, P>::LIMIT_EXCEEDED);
                    }
                    for _ in 0..count {
                        descriptor(&mut r)?;
                    }
                    list = Some(&before[..before.len() - r.remaining().len()]);
                }
                Field::Extensions => extensions = P::extensions(&mut r, make)?,
                Field::Options => options = Options::read(&mut r, make)?,
                Field::Auth => {
                    let value = r.bytes_checked(|length| {
                        admit_length::<ParseError<'a, P>>(length, 0, crate::client_pin::KEY_BYTES)
                    })?;
                    auth = Some(value);
                }
                Field::Protocol => {
                    let value = r.parameter_uint()?;
                    if crate::client_pin::Protocol::decode(value).is_none() {
                        return Err(ParseError::<'a, P>::INVALID_PARAMETER);
                    }
                    protocol = Some(value);
                }
                // Enterprise attestation is not advertised by this profile.
                Field::Enterprise => {
                    r.uint()?;
                    return Err(ParseError::<'a, P>::INVALID_PARAMETER);
                }
                _ => {
                    r.skip_unknown()?;
                }
            }
        }
        if !r.done() {
            return Err(ParseError::<'a, P>::INVALID_CBOR);
        }
        P::Reader::validate(bytes)?;
        if hash.is_none() || rp.is_none() || (make && (user.is_none() || algorithms.is_none())) {
            return Err(ParseError::<'a, P>::MISSING_PARAMETER);
        }
        if make && algorithm_count == 0 {
            return Err(ParseError::<'a, P>::UNSUPPORTED_ALGORITHM);
        }
        schema::admit_auth::<ParseError<'a, P>>(
            protocol.unwrap_or(0) as u8,
            auth.map(|value| value.len()),
        )?;
        let rp = rp.ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?;
        if rp.is_empty() || rp.len() > RP_ID_MAX {
            return Err(ParseError::<'a, P>::INVALID_LENGTH);
        }
        Ok(Self {
            client_hash: hash.ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?,
            rp,
            user_id: user,
            user_name,
            user_display,
            extensions,
            algorithms,
            list,
            options,
            auth,
            protocol,
        })
    }
    pub fn algorithm(&self, vcap: bool) -> Result<P::Algorithm, ParseError<'a, P>> {
        let mut r = P::Reader::new(
            self.algorithms
                .ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?,
        );
        let mut selected = None;
        for _ in 0..r.array()? {
            let (kind, algorithm) = algorithm_entry(&mut r)?;
            let supported =
                algorithm.and_then(|algorithm| P::algorithm(kind, i64::from(algorithm), vcap));
            if selected.is_none() {
                selected = supported;
            }
        }
        selected.ok_or(ParseError::<'a, P>::UNSUPPORTED_ALGORITHM)
    }
}
fn admit_length<E: Error>(length: usize, minimum: usize, maximum: usize) -> Result<(), E> {
    if (minimum..=maximum).contains(&length) {
        Ok(())
    } else {
        Err(E::INVALID_LENGTH)
    }
}
pub struct List<'a, R: Reader<'a>> {
    reader: R,
    lifetime: core::marker::PhantomData<&'a [u8]>,
    remaining: usize,
}
impl<'a, R: Reader<'a>> List<'a, R> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, R::Error> {
        let mut reader = R::new(bytes);
        let remaining = reader.array()?;
        if remaining > super::MAX_LIST {
            return Err(R::Error::LIMIT_EXCEEDED);
        }
        Ok(Self {
            reader,
            remaining,
            lifetime: core::marker::PhantomData,
        })
    }
}
impl<'a, R: Reader<'a>> Iterator for List<'a, R> {
    type Item = Result<Option<&'a [u8]>, R::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(descriptor(&mut self.reader))
    }
}
fn descriptor<'a, R: Reader<'a>>(reader: &mut R) -> Result<Option<&'a [u8]>, R::Error> {
    let (mut kind, mut id) = (None, None);
    let mut order = TextOrder::new();
    for _ in 0..reader.map()? {
        match order.next(reader)? {
            "type" => kind = Some(reader.text()?),
            "id" => id = Some(reader.bytes()?),
            _ => reader.skip_unknown()?,
        }
    }
    let kind = kind.ok_or(R::Error::MISSING_PARAMETER)?;
    let id = id.ok_or(R::Error::MISSING_PARAMETER)?;
    Ok(if kind == "public-key" { Some(id) } else { None })
}
