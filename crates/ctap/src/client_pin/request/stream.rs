// SPDX-License-Identifier: Apache-2.0
//! ClientPIN field admission shared by owned streaming and borrowed requests.
use super::{Command, EncryptedField, LengthError, PermissionPolicy, Protocol};
use crate::request::{
    agreement,
    credential::RP_ID_MAX,
    stream::{self, Key},
};
use canokey_protocol::cbor::Event;

pub trait Error: crate::request::Error {
    const INVALID_SUBCOMMAND: Self;
    const UNAUTHORIZED_PERMISSION: Self;
    const PIN_POLICY: Self;
}
impl Error for crate::status::Status {
    const INVALID_SUBCOMMAND: Self = Self::InvalidSubcommand;
    const UNAUTHORIZED_PERMISSION: Self = Self::UnauthorizedPermission;
    const PIN_POLICY: Self = Self::PinPolicyViolation;
}
fn schema_error<E: Error>(error: super::Error) -> E {
    match error {
        super::Error::MissingParameter => E::MISSING_PARAMETER,
        super::Error::InvalidParameter => E::INVALID_PARAMETER,
        super::Error::UnauthorizedPermission => E::UNAUTHORIZED_PERMISSION,
    }
}

/// Products retain their existing backing. Header admission always precedes
/// start/body callbacks; borrowed consumers record spans instead of copying.
pub trait Output<E: Error> {
    fn protocol(&self) -> u8;
    fn subcommand(&self) -> u8;
    fn permissions(&self) -> u16;
    fn rp_present(&self) -> bool;
    fn set_protocol(&mut self, value: u8);
    fn set_subcommand(&mut self, value: u8);
    fn set_permissions(&mut self, value: u16);
    fn agreement(&mut self) -> &mut [u8; crate::client_pin::agreement::POINT_BYTES];
    fn start(&mut self, label: i8, offset: u16, length: u16);
    fn body(&mut self, event: &Event<'_>, body: &mut Option<(i8, usize)>) -> Result<(), E>;
}

// Outside all recognized ClientPIN labels; full-width unknown keys are skipped.
const UNKNOWN_LABEL: i8 = 127;

pub struct Fields<E: Error, O: Output<E>> {
    pub output: O,
    started: bool,
    previous: Option<Key<E>>,
    agreement: agreement::Parser<E>,
    key: Option<Option<i8>>,
    cose: bool,
    seen: u16,
    skip_depth: u8,
    body: Option<(i8, usize)>,
}
impl<E: Error, O: Output<E>> Fields<E, O> {
    pub const fn new(output: O) -> Self {
        Self {
            output,
            started: false,
            previous: None,
            agreement: agreement::Parser::new(),
            key: None,
            cose: false,
            seen: 0x0000,
            skip_depth: 0,
            body: None,
        }
    }
    pub fn finish(&self) -> Result<Command, E> {
        let output = &self.output;
        if self.seen & (1 << super::LABEL_SUBCOMMAND) == 0x0000 {
            return Err(E::MISSING_PARAMETER);
        }
        let command =
            Command::decode(u64::from(output.subcommand())).ok_or(E::INVALID_SUBCOMMAND)?;
        if command == Command::Retries {
            return Ok(command);
        }
        super::admit(
            command,
            self.seen,
            output.permissions(),
            output.rp_present(),
        )
        .map_err(schema_error::<E>)?;
        Ok(command)
    }
    pub fn event(
        &mut self,
        event: &Event<'_>,
        offset: u16,
        permissions: PermissionPolicy,
    ) -> Result<(), E> {
        let output = &mut self.output;
        use super::{
            LABEL_AGREEMENT, LABEL_AUTH, LABEL_NEW_PIN, LABEL_PERMISSIONS, LABEL_PIN_HASH,
            LABEL_PROTOCOL, LABEL_RP_ID, LABEL_SUBCOMMAND,
        };
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(E::UNEXPECTED_TYPE);
            }
            self.started = true;
            return Ok(());
        }
        if self.cose {
            if self
                .agreement
                .event(event, output.agreement(), E::INVALID_CBOR)?
            {
                self.cose = false;
            }
            return Ok(());
        }
        if stream::skip_cbor_event(&mut self.skip_depth, event)? {
            return Ok(());
        }
        if self.body.is_some() {
            output.body(event, &mut self.body)?;
            return Ok(());
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            self.key = Some(Key::ordered(event, &mut self.previous)?);
            return Ok(());
        };
        let key = key.unwrap_or(UNKNOWN_LABEL);
        if (LABEL_PROTOCOL..=LABEL_PIN_HASH).contains(&key)
            || key == LABEL_PERMISSIONS
            || key == LABEL_RP_ID
        {
            self.seen |= 1 << key;
        }
        match key {
            LABEL_PROTOCOL => match *event {
                Event::Unsigned(n) if Protocol::decode(n).is_some() => output.set_protocol(n as u8),
                Event::Unsigned(_) | Event::Negative(_) => return Err(E::INVALID_PARAMETER),
                _ => return Err(E::UNEXPECTED_TYPE),
            },
            LABEL_SUBCOMMAND => match *event {
                Event::Unsigned(n) => {
                    output.set_subcommand(u8::try_from(n).map_err(|_| E::INVALID_SUBCOMMAND)?)
                }
                Event::Negative(_) => return Err(E::INVALID_SUBCOMMAND),
                _ => return Err(E::UNEXPECTED_TYPE),
            },
            LABEL_AGREEMENT => {
                if !matches!(event, Event::Map(_)) {
                    return Err(E::UNEXPECTED_TYPE);
                }
                self.cose = true;
            }
            LABEL_AUTH..=LABEL_PIN_HASH => {
                let protocol =
                    Protocol::decode(u64::from(output.protocol())).ok_or(E::MISSING_PARAMETER)?;
                let field = match key {
                    LABEL_AUTH => EncryptedField::Auth,
                    LABEL_NEW_PIN => EncryptedField::NewPin,
                    _ => EncryptedField::PinHash,
                };
                let Event::Bytes(length) = *event else {
                    return Err(E::UNEXPECTED_TYPE);
                };
                field
                    .validate(protocol, usize::from(length))
                    .map_err(|error| match error {
                        LengthError::PinTooLong => E::PIN_POLICY,
                        LengthError::WrongLength => E::INVALID_CBOR,
                    })?;
                output.start(key, offset, length);
                self.body = Some((key, 0));
            }
            LABEL_PERMISSIONS => match *event {
                Event::Unsigned(n) => {
                    // Only native capability restrictions depend on protocol.
                    // A missing protocol remains a finish-time required field.
                    let protocol =
                        Protocol::decode(u64::from(output.protocol())).unwrap_or(Protocol::Two);
                    output.set_permissions(
                        permissions
                            .validate(protocol, n)
                            .map_err(schema_error::<E>)?,
                    );
                }
                Event::Negative(_) => return Err(E::UNAUTHORIZED_PERMISSION),
                _ => return Err(E::UNEXPECTED_TYPE),
            },
            LABEL_RP_ID => match *event {
                Event::Text(n) if n > 0 && usize::from(n) <= RP_ID_MAX => {
                    output.start(key, offset, n);
                    self.body = Some((key, 0));
                }
                Event::Text(_) => return Err(E::INVALID_PARAMETER),
                _ => return Err(E::UNEXPECTED_TYPE),
            },
            _ => self.skip(event),
        }
        Ok(())
    }
    fn skip(&mut self, event: &Event<'_>) {
        if stream::is_cbor_container(event) {
            self.skip_depth = 1;
        }
    }
}
