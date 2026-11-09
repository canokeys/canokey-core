// SPDX-License-Identifier: Apache-2.0
//! Frozen pre-extraction production parser, used only as a differential oracle.
use super::super::wire::pin_protocol as wire;
use super::super::{Command, Key, Status};
use canokey_ctap::client_pin::{Protocol, request as schema};
use canokey_protocol::cbor::Event;

fn schema_error(error: schema::Error) -> Status {
    match error {
        schema::Error::MissingParameter => Status::MissingParameter,
        schema::Error::InvalidParameter => Status::InvalidParameter,
        schema::Error::UnauthorizedPermission => Status::UnauthorizedPermission,
    }
}

// Sentinel for a non-integer/unsupported-width label. It is outside the
// recognized clientPIN labels 1..=6, 9 and 10 and follows the skip path.
const COSE_KEY_MISSING: i8 = 127;

#[repr(C)]
pub struct Parameters {
    pub protocol: u8,
    pub subcommand: u8,
    pub permissions: u8,
    pub rp_len: usize,
    pub agreement: [u8; 64],
    pub auth: [u8; 32],
    pub new_pin: [u8; wire::NEW_PIN_V2_BYTES],
    pub pin_hash: [u8; 32],
    pub rp: [u8; super::super::wire::RP_ID_MAX],
}
impl Parameters {
    const fn new() -> Self {
        Self {
            protocol: 0,
            subcommand: 0,
            agreement: [0; 64],
            auth: [0; 32],
            new_pin: [0; wire::NEW_PIN_V2_BYTES],
            pin_hash: [0; 32],
            permissions: 0,
            rp: [0; super::super::wire::RP_ID_MAX],
            rp_len: 0,
        }
    }
}
pub struct Parser {
    decoder: super::super::request_decoder::RequestDecoder,
    fields: Fields,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            decoder: super::super::request_decoder::RequestDecoder::new(),
            fields: Fields::new(),
        }
    }
    // Share this parser across HID and APDU callers on size-constrained targets.
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let fields = &mut self.fields;
        self.decoder
            .consume(bytes, &mut |event, _| fields.event(event));
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let f = &mut self.fields;
        if f.seen & (1 << schema::LABEL_SUBCOMMAND) == 0 {
            return Err(Status::MissingParameter);
        }
        let command = schema::Command::decode(u64::from(f.params.subcommand))
            .ok_or(Status::InvalidSubcommand)?;
        if f.params.subcommand == schema::Command::Retries as u8 {
            return Ok(Command::GetPinRetries);
        }
        schema::admit(
            command,
            f.seen,
            u16::from(f.params.permissions),
            f.params.rp_len != 0,
        )
        .map_err(schema_error)?;
        if f.params.subcommand == schema::Command::Agreement as u8 {
            Ok(Command::GetKeyAgreement)
        } else {
            Ok(Command::ClientPin(super::Parameters {
                protocol: f.params.protocol,
                subcommand: f.params.subcommand,
                permissions: f.params.permissions,
                rp_len: f.params.rp_len,
                agreement: f.params.agreement,
                auth: f.params.auth,
                new_pin: f.params.new_pin,
                pin_hash: f.params.pin_hash,
                rp: f.params.rp,
            }))
        }
    }
}
struct Fields {
    params: Parameters,
    started: bool,
    previous: Option<Key>,
    agreement: super::super::agreement::Parser,
    key: Option<Option<i8>>,
    cose: bool,
    seen: u16,
    skip_depth: u8,
    body: Option<(i8, usize)>,
}
impl Fields {
    const fn new() -> Self {
        Self {
            params: Parameters::new(),
            started: false,
            previous: None,
            agreement: super::super::agreement::Parser::new(),
            key: None,
            cose: false,
            seen: 0,
            skip_depth: 0,
            body: None,
        }
    }
    fn event(&mut self, event: &Event<'_>) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if self.cose {
            if self
                .agreement
                .event(event, &mut self.params.agreement, Status::InvalidCbor)?
            {
                self.cose = false;
            }
            return Ok(());
        }
        if super::super::skip_cbor_event(&mut self.skip_depth, event)? {
            return Ok(());
        }
        if let Some((key, _)) = self.body {
            let dest: &mut [u8] = match key {
                schema::LABEL_AUTH => &mut self.params.auth,
                schema::LABEL_NEW_PIN => &mut self.params.new_pin,
                schema::LABEL_PIN_HASH => &mut self.params.pin_hash,
                schema::LABEL_RP_ID => &mut self.params.rp,
                _ => return Err(Status::InvalidCbor),
            };
            super::super::consume_cbor_body(event, &mut self.body, dest)?;
            return Ok(());
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            let key = Key::ordered(event, &mut self.previous)?;
            self.key = Some(key);
            return Ok(());
        };
        let key = key.unwrap_or(COSE_KEY_MISSING);

        if (schema::LABEL_PROTOCOL..=schema::LABEL_PIN_HASH).contains(&key)
            || key == schema::LABEL_PERMISSIONS
            || key == schema::LABEL_RP_ID
        {
            self.seen |= 1 << key;
        }
        match key {
            schema::LABEL_PROTOCOL => match *event {
                Event::Unsigned(n) if Protocol::decode(n).is_some() => {
                    self.params.protocol = n as u8
                }
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            schema::LABEL_SUBCOMMAND => match *event {
                Event::Unsigned(n) => {
                    self.params.subcommand =
                        u8::try_from(n).map_err(|_| Status::InvalidSubcommand)?
                }
                Event::Negative(_) => return Err(Status::InvalidSubcommand),
                _ => return Err(Status::UnexpectedType),
            },
            schema::LABEL_AGREEMENT => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.cose = true;
            }
            schema::LABEL_AUTH..=schema::LABEL_PIN_HASH => {
                if self.params.protocol == 0 {
                    return Err(Status::MissingParameter);
                }
                let field = match key {
                    schema::LABEL_AUTH => schema::EncryptedField::Auth,
                    schema::LABEL_NEW_PIN => schema::EncryptedField::NewPin,
                    _ => schema::EncryptedField::PinHash,
                };
                let protocol = Protocol::decode(u64::from(self.params.protocol))
                    .ok_or(Status::InvalidParameter)?;
                self.bytes(key, event, protocol, field)?;
            }
            schema::LABEL_PERMISSIONS => match *event {
                Event::Unsigned(n) => {
                    // Core rejects all bits above the defined standard mask.
                    let policy = schema::PermissionPolicy {
                        supported: u16::from(wire::PERMISSION_MASK),
                        rejected: u64::from(wire::PERMISSION_BIO),
                        maximum: Some(u64::from(wire::PERMISSION_MASK)),
                        protocol_two_only: 0x00,
                    };
                    // Permission admission is protocol-independent in this profile.
                    self.params.permissions =
                        policy.validate(Protocol::Two, n).map_err(schema_error)? as u8;
                }
                Event::Negative(_) => return Err(Status::UnauthorizedPermission),
                _ => return Err(Status::UnexpectedType),
            },
            schema::LABEL_RP_ID => match *event {
                Event::Text(n) if n > 0 && usize::from(n) <= super::super::wire::RP_ID_MAX => {
                    self.params.rp_len = usize::from(n);
                    self.body = Some((schema::LABEL_RP_ID, 0));
                }
                Event::Text(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            _ => self.skip(event),
        }
        Ok(())
    }
    fn bytes(
        &mut self,
        key: i8,
        event: &Event<'_>,
        protocol: Protocol,
        field: schema::EncryptedField,
    ) -> Result<(), Status> {
        match *event {
            Event::Bytes(length) => {
                field
                    .validate(protocol, usize::from(length))
                    .map_err(|error| match error {
                        schema::LengthError::PinTooLong => Status::PinPolicy,
                        schema::LengthError::WrongLength => Status::InvalidCbor,
                    })?;
                self.body = Some((key, 0));
                Ok(())
            }
            _ => Err(Status::UnexpectedType),
        }
    }
    fn skip(&mut self, event: &Event<'_>) {
        if super::super::is_cbor_container(event) {
            self.skip_depth = 1;
        }
    }
}

