// SPDX-License-Identifier: Apache-2.0
//! Borrowed credential schema. The reader and extension/algorithm profile keep
//! product admission and error identity; slices borrow the caller's input only.
use super::{
    RP_ID_MAX,
    schema::{self, Field},
};
use crate::request::Error;

pub trait Reader<'a>: Sized {
    type Error: Error;
    fn new(bytes: &'a [u8]) -> Self;
    fn validate(bytes: &'a [u8]) -> Result<(), Self::Error>;
    fn done(&self) -> bool;
    fn map(&mut self) -> Result<usize, Self::Error>;
    fn array(&mut self) -> Result<usize, Self::Error>;
    fn uint(&mut self) -> Result<u64, Self::Error>;
    fn int(&mut self) -> Result<i64, Self::Error>;
    fn boolean(&mut self) -> Result<bool, Self::Error>;
    fn text(&mut self) -> Result<&'a str, Self::Error>;
    fn bytes(&mut self) -> Result<&'a [u8], Self::Error>;
    fn item(&mut self) -> Result<&'a [u8], Self::Error>;
}

pub trait Profile<'a> {
    type Reader: Reader<'a>;
    type Extensions: Default;
    type Algorithm;
    fn extensions(bytes: &'a [u8], make: bool) -> Result<Self::Extensions, ParseError<'a, Self>>;
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
    fn decode<'a, R: Reader<'a>>(bytes: &'a [u8], make: bool) -> Result<Self, R::Error> {
        let mut r = R::new(bytes);
        let mut options = Self::default();
        for _ in 0..r.map()? {
            let key = r.text()?;
            let field = schema::text_field(schema::Context::Options, key.as_bytes(), make);
            match field {
                Field::Resident | Field::Up | Field::Uv => {
                    let value = r.boolean()?;
                    schema::admit_option::<R::Error>(make, field)?;
                    match field {
                        Field::Resident => options.rk = value,
                        Field::Up => options.up = Some(value),
                        _ => options.uv = value,
                    }
                }
                _ => {
                    r.item()?;
                }
            }
        }
        Ok(options)
    }
}
pub struct Request<'a, P: Profile<'a>> {
    pub client_hash: &'a [u8; 32],
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
fn entity<'a, R: Reader<'a>>(bytes: &'a [u8], user: bool) -> Result<&'a [u8], R::Error> {
    let mut r = R::new(bytes);
    let mut id = None;
    for _ in 0..r.map()? {
        match r.text()? {
            "id" => {
                id = Some(if user {
                    r.bytes()?
                } else {
                    r.text()?.as_bytes()
                })
            }
            "name" | "displayName" | "icon" => {
                r.text()?;
            }
            _ => {
                r.item()?;
            }
        }
    }
    let id = id.ok_or(R::Error::MISSING_PARAMETER)?;
    if user && (id.is_empty() || id.len() > 64) {
        return Err(R::Error::INVALID_LENGTH);
    }
    Ok(id)
}
impl<'a, P: Profile<'a>> Request<'a, P> {
    #[inline(never)]
    pub fn decode(bytes: &'a [u8], make: bool) -> Result<Self, ParseError<'a, P>> {
        P::Reader::validate(bytes)?;
        let mut r = P::Reader::new(bytes);
        let (mut hash, mut rp, mut user, mut algorithms, mut list, mut auth, mut protocol) =
            (None, None, None, None, None, None, None);
        let mut options = Options::default();
        let (mut user_name, mut user_display) = (None, None);
        let mut extensions = P::Extensions::default();
        for _ in 0..r.map()? {
            let key = r.uint()?;
            match schema::root_field(i8::try_from(key).ok(), make) {
                Field::ClientHash => hash = Some(r.bytes()?),
                Field::Rp if make => {
                    rp = Some(
                        core::str::from_utf8(entity::<P::Reader>(r.item()?, false)?)
                            .map_err(|_| ParseError::<'a, P>::INVALID_CBOR)?,
                    );
                }
                Field::Rp => rp = Some(r.text()?),
                Field::User => {
                    let bytes = r.item()?;
                    user = Some(entity::<P::Reader>(bytes, true)?);
                    let mut u = P::Reader::new(bytes);
                    for _ in 0..u.map()? {
                        match u.text()? {
                            "name" => user_name = Some(u.text()?),
                            "displayName" => user_display = Some(u.text()?),
                            _ => {
                                u.item()?;
                            }
                        }
                    }
                }
                Field::Algorithms => algorithms = Some(r.item()?),
                Field::List => list = Some(r.item()?),
                Field::Extensions => extensions = P::extensions(r.item()?, make)?,
                Field::Options => options = Options::decode::<P::Reader>(r.item()?, make)?,
                Field::Auth => auth = Some(r.bytes()?),
                Field::Protocol => protocol = Some(r.uint()?),
                // Enterprise attestation is not advertised by this profile.
                Field::Enterprise => return Err(ParseError::<'a, P>::INVALID_PARAMETER),
                _ => {
                    r.item()?;
                }
            }
        }
        if !r.done() {
            return Err(ParseError::<'a, P>::INVALID_CBOR);
        }
        if make && (user.is_none() || algorithms.is_none()) {
            return Err(ParseError::<'a, P>::MISSING_PARAMETER);
        }
        if let Some(list) = list {
            for entry in List::<P::Reader>::new(list)? {
                entry?;
            }
        }
        let rp = rp.ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?;
        if rp.is_empty() || rp.len() > RP_ID_MAX {
            return Err(ParseError::<'a, P>::INVALID_LENGTH);
        }
        Ok(Self {
            client_hash: hash
                .ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?
                .try_into()
                .map_err(|_| ParseError::<'a, P>::INVALID_LENGTH)?,
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
            let (mut kind, mut alg) = (None, None);
            for _ in 0..r.map()? {
                match r.text()? {
                    "alg" => alg = Some(r.int()?),
                    "type" => kind = Some(r.text()?),
                    _ => {
                        r.item()?;
                    }
                }
            }
            let kind = kind.ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?;
            let alg = alg.ok_or(ParseError::<'a, P>::MISSING_PARAMETER)?;
            let supported = P::algorithm(kind, alg, vcap);
            if selected.is_none() {
                selected = supported;
            }
        }
        selected.ok_or(ParseError::<'a, P>::UNSUPPORTED_ALGORITHM)
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
        Some((|| {
            let (mut kind, mut id) = (None, None);
            for _ in 0..self.reader.map()? {
                match self.reader.text()? {
                    "type" => kind = Some(self.reader.text()?),
                    "id" => id = Some(self.reader.bytes()?),
                    _ => {
                        self.reader.item()?;
                    }
                }
            }
            let kind = kind.ok_or(R::Error::MISSING_PARAMETER)?;
            let id = id.ok_or(R::Error::MISSING_PARAMETER)?;
            Ok(if kind == "public-key" { Some(id) } else { None })
        })())
    }
}
