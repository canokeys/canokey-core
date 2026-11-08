// SPDX-License-Identifier: Apache-2.0
//! Incremental clientPIN schema. Only owned fields survive request release.
use super::wire::pin_protocol as wire;
use super::{Command, Key, Status};
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
    pub rp: [u8; super::wire::RP_ID_MAX],
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
            rp: [0; super::wire::RP_ID_MAX],
            rp_len: 0,
        }
    }
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::new(),
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
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        memory.wipe(&mut self.fields.params.agreement);
        memory.wipe(&mut self.fields.params.auth);
        memory.wipe(&mut self.fields.params.new_pin);
        memory.wipe(&mut self.fields.params.pin_hash);
        memory.wipe(&mut self.fields.params.rp);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let f = &mut self.fields;
        if f.seen & (1 << wire::LABEL_SUBCOMMAND) == 0 {
            return Err(Status::MissingParameter);
        }
        let command = schema::Command::decode(u64::from(f.params.subcommand))
            .ok_or(Status::InvalidSubcommand)?;
        if f.params.subcommand == wire::GET_RETRIES {
            return Ok(Command::GetPinRetries);
        }
        schema::admit(
            command,
            f.seen,
            u16::from(f.params.permissions),
            f.params.rp_len != 0,
            schema::ValidationOrder::RequiredFirst,
        )
        .map_err(schema_error)?;
        if f.params.subcommand == wire::GET_AGREEMENT {
            Ok(Command::GetKeyAgreement)
        } else {
            Ok(Command::ClientPin(core::mem::replace(
                &mut f.params,
                Parameters::new(),
            )))
        }
    }
}
struct Fields {
    params: Parameters,
    started: bool,
    previous: Option<Key>,
    agreement: super::agreement::Parser,
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
            agreement: super::agreement::Parser::new(),
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
        if super::skip_cbor_event(&mut self.skip_depth, event)? {
            return Ok(());
        }
        if let Some((key, _)) = self.body {
            let dest: &mut [u8] = match key {
                wire::LABEL_AUTH => &mut self.params.auth,
                wire::LABEL_NEW_PIN => &mut self.params.new_pin,
                wire::LABEL_PIN_HASH => &mut self.params.pin_hash,
                wire::LABEL_RP_ID => &mut self.params.rp,
                _ => return Err(Status::InvalidCbor),
            };
            super::consume_cbor_body(event, &mut self.body, dest)?;
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

        if (wire::LABEL_PROTOCOL..=wire::LABEL_PIN_HASH).contains(&key)
            || key == wire::LABEL_PERMISSIONS
            || key == wire::LABEL_RP_ID
        {
            self.seen |= 1 << key;
        }
        match key {
            wire::LABEL_PROTOCOL => match *event {
                Event::Unsigned(n) if Protocol::decode(n).is_some() => {
                    self.params.protocol = n as u8
                }
                Event::Unsigned(_) | Event::Negative(_) => return Err(Status::InvalidParameter),
                _ => return Err(Status::UnexpectedType),
            },
            wire::LABEL_SUBCOMMAND => match *event {
                Event::Unsigned(n) => {
                    self.params.subcommand =
                        u8::try_from(n).map_err(|_| Status::InvalidSubcommand)?
                }
                Event::Negative(_) => return Err(Status::InvalidSubcommand),
                _ => return Err(Status::UnexpectedType),
            },
            wire::LABEL_AGREEMENT => {
                if !matches!(event, Event::Map(_)) {
                    return Err(Status::UnexpectedType);
                }
                self.cose = true;
            }
            wire::LABEL_AUTH..=wire::LABEL_PIN_HASH => {
                if self.params.protocol == 0 {
                    return Err(Status::MissingParameter);
                }
                let field = match key {
                    wire::LABEL_AUTH => schema::EncryptedField::Auth,
                    wire::LABEL_NEW_PIN => schema::EncryptedField::NewPin,
                    _ => schema::EncryptedField::PinHash,
                };
                let protocol = Protocol::decode(u64::from(self.params.protocol))
                    .ok_or(Status::InvalidParameter)?;
                self.bytes(key, event, protocol, field)?;
            }
            wire::LABEL_PERMISSIONS => match *event {
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
            wire::LABEL_RP_ID => match *event {
                Event::Text(n) if n > 0 && usize::from(n) <= super::wire::RP_ID_MAX => {
                    self.params.rp_len = usize::from(n);
                    self.body = Some((wire::LABEL_RP_ID, 0));
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
        if super::is_cbor_container(event) {
            self.skip_depth = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_pin_length_policy_is_identical_at_every_fragment_boundary() {
        for protocol in [1, 2] {
            let expected = if protocol == 1 { 64 } else { 80 };
            for command in [3, 4] {
                for length in [0, expected - 1, expected, expected + 1, expected + 16, 240] {
                    let mut wire = [0u8; 248];
                    wire[..6].copy_from_slice(&[0xa3, 1, protocol, 2, command, 5]);
                    let header = if length == 0 {
                        wire[6] = 0x40;
                        7
                    } else {
                        wire[6..8].copy_from_slice(&[0x58, length as u8]);
                        8
                    };
                    let wire = &wire[..header + length];
                    let status = if length > expected {
                        Status::PinPolicy
                    } else if length < expected {
                        Status::InvalidCbor
                    } else {
                        Status::MissingParameter
                    };
                    for split in 0..=wire.len() {
                        let mut parser = Parser::new();
                        parser.consume(&wire[..split]);
                        parser.consume(&wire[split..]);
                        assert!(
                            matches!(parser.finish(), Err(e) if e == status),
                            "protocol={protocol} command={command} length={length} split={split}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn incremental_first_errors_survive_every_fragment_boundary() {
        // Each map deliberately has more than one problem. Streaming admission
        // keeps the first field error; finish checks required fields before scope.
        for (bytes, expected) in [
            (
                &[0xa3, 0x01, 0x02, 0x02, 0x05, 0x09, 0x01][..],
                Status::MissingParameter,
            ),
            (
                &[0xa3, 0x01, 0x02, 0x02, 0x09, 0x09, 0x18, 0x40][..],
                Status::UnauthorizedPermission,
            ),
            (
                &[0xa3, 0x01, 0x01, 0x02, 0x09, 0x09, 0x00][..],
                Status::InvalidParameter,
            ),
            (
                &[0xa2, 0x02, 0x01, 0x05, 0x40][..],
                Status::MissingParameter,
            ),
            (
                &[0xa2, 0x01, 0x03, 0x02, 0x01][..],
                Status::InvalidParameter,
            ),
            (
                &[0xa2, 0x01, 0x02, 0x02, 0x08][..],
                Status::InvalidSubcommand,
            ),
        ] {
            for split in 0..=bytes.len() {
                let mut parser = Parser::new();
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..]);
                assert!(
                    matches!(parser.finish(), Err(error) if error == expected),
                    "split={split} bytes={bytes:?}"
                );
            }
        }
    }
}
