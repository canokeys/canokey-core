// SPDX-License-Identifier: Apache-2.0
//! Credential-management schema and synchronous authenticated command flow.
use crate::{credential::Id, resident::RP_HASH_BYTES};
pub mod borrowed;
pub mod stream;

// CTAP 2.1 §6.8 credentialManagement subcommands and optional vendor metadata.
pub const METADATA: u8 = 0x01;
pub const RP_BEGIN: u8 = 0x02;
pub const RP_NEXT: u8 = 0x03;
pub const CREDENTIAL_BEGIN: u8 = 0x04;
pub const CREDENTIAL_NEXT: u8 = 0x05;
pub const DELETE: u8 = 0x06;
pub const UPDATE_USER: u8 = 0x07;
pub const VENDOR_METADATA_ONLY: u8 = 0x80;
pub const VENDOR_ALGORITHM: u8 = 0x80;
pub const USER_ID_MAX: usize = 64;
// CTAP 2.1 §6.8 credentialManagement request map labels.
pub const SUBCOMMAND: u64 = 0x01;
pub const PARAMETERS: u64 = 0x02;
pub const PIN_PROTOCOL: u64 = 0x03;
pub const PIN_AUTH: u64 = 0x04;

pub trait Error: crate::request::Error {
    const NO_CREDENTIALS: Self;
    const PUAT_REQUIRED: Self;
    const INVALID_SUBCOMMAND: Self;
    const NOT_ALLOWED: Self;
}
impl Error for crate::status::Status {
    const NO_CREDENTIALS: Self = Self::NoCredentials;
    const PUAT_REQUIRED: Self = Self::PuatRequired;
    const INVALID_SUBCOMMAND: Self = Self::InvalidSubcommand;
    const NOT_ALLOWED: Self = Self::NotAllowed;
}
pub fn subcommand<E: crate::request::Error>(value: u64) -> Result<u8, E> {
    u8::try_from(value).map_err(|_| E::INVALID_PARAMETER)
}
pub fn protocol<E: crate::request::Error>(value: u64) -> Result<u8, E> {
    crate::client_pin::Protocol::decode(value)
        .map(|value| value as u8)
        .ok_or(E::INVALID_PARAMETER)
}
pub fn auth_length<E: crate::request::Error>(length: usize) -> Result<(), E> {
    use crate::client_pin::Protocol;
    if length == Protocol::One.auth_bytes() || length == Protocol::Two.auth_bytes() {
        Ok(())
    } else {
        Err(E::INVALID_PARAMETER)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct User<'a> {
    pub id: &'a [u8],
    pub name: Option<&'a str>,
    pub display: Option<&'a str>,
}
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Fields<'a> {
    pub rp: Option<&'a [u8; RP_HASH_BYTES]>,
    pub id: Option<&'a Id>,
    pub user: Option<User<'a>>,
    pub metadata_only: bool,
}
pub struct Request {
    pub subcommand: u8,
    pub authenticated: bool,
    pub protocol: bool,
    pub rp: bool,
    pub credential: bool,
    pub user: bool,
}
impl Request {
    pub fn new(subcommand: u8, authenticated: bool, protocol: bool, fields: &Fields<'_>) -> Self {
        Self {
            subcommand,
            authenticated,
            protocol,
            rp: fields.rp.is_some(),
            credential: fields.id.is_some(),
            user: fields.user.is_some(),
        }
    }
}
/// Callbacks borrow the product's sole session, records and output for this call.
/// Mutations authenticate before record IO without committing use, then resolve
/// the stored RP before mutation. Storage publication and output leases stay in
/// the adapter; none of these hooks may retain a loan or reenter the applet.
pub trait Backend {
    type Error: Error;
    type Output;
    fn reset_cursor(&mut self);
    fn cursor_mode(&self) -> u8;
    fn continue_live(&mut self) -> Result<(), Self::Error>;
    fn authorize(&mut self, deferred_rp: bool) -> Result<(), Self::Error>;
    fn begin(&mut self) {}
    fn metadata(&mut self) -> Result<Self::Output, Self::Error>;
    fn rps(&mut self, first: bool) -> Result<Self::Output, Self::Error>;
    fn credentials(&mut self, first: bool) -> Result<Self::Output, Self::Error>;
    fn mutate(&mut self, delete: bool) -> Result<Self::Output, Self::Error>;
}
#[inline]
pub fn execute<B: Backend>(request: Request, backend: &mut B) -> Result<B::Output, B::Error> {
    use crate::request::Error as _;
    if !(METADATA..=UPDATE_USER).contains(&request.subcommand) {
        return Err(B::Error::INVALID_SUBCOMMAND);
    }
    let command = request.subcommand;
    let continued = matches!(command, RP_NEXT | CREDENTIAL_NEXT);
    if continued {
        if backend.cursor_mode() != command {
            return Err(B::Error::NOT_ALLOWED);
        }
        backend.continue_live()?;
    } else {
        backend.reset_cursor();
        if !request.authenticated {
            return Err(B::Error::PUAT_REQUIRED);
        }
        if !request.protocol {
            return Err(B::Error::MISSING_PARAMETER);
        }
        if command == CREDENTIAL_BEGIN && !request.rp
            || matches!(command, DELETE | UPDATE_USER) && !request.credential
            || command == UPDATE_USER && !request.user
        {
            return Err(B::Error::MISSING_PARAMETER);
        }
        backend.authorize(matches!(command, DELETE | UPDATE_USER))?;
        if matches!(command, RP_BEGIN | CREDENTIAL_BEGIN) {
            backend.begin();
        }
    }
    // Only enumeration may create a cursor. Metadata and mutations retain the
    // empty cursor established before authorization, including on failure.
    match command {
        METADATA => backend.metadata(),
        RP_BEGIN | RP_NEXT => backend.rps(!continued),
        CREDENTIAL_BEGIN | CREDENTIAL_NEXT => backend.credentials(!continued),
        DELETE | UPDATE_USER => backend.mutate(command == DELETE),
        _ => unreachable!(),
    }
}
/// Empty enumeration differs from an exhausted continuation, in both products.
pub fn exhausted<E: Error>(first: bool) -> E {
    if first {
        E::NO_CREDENTIALS
    } else {
        E::NOT_ALLOWED
    }
}
