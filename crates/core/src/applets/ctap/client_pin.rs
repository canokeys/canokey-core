// SPDX-License-Identifier: Apache-2.0
//! Owned ClientPIN backing for the shared incremental field state machine.
use super::wire::pin_protocol as wire;
use super::{Command, Status};
use canokey_ctap::client_pin::request::{self as schema, stream};

impl stream::Error for Status {
    const INVALID_SUBCOMMAND: Self = Self::InvalidSubcommand;
    const UNAUTHORIZED_PERMISSION: Self = Self::UnauthorizedPermission;
    const PIN_POLICY: Self = Self::PinPolicy;
}
const PERMISSIONS: schema::PermissionPolicy = schema::PermissionPolicy {
    supported: wire::PERMISSION_MASK as u16,
    rejected: wire::PERMISSION_BIO as u64,
    maximum: Some(wire::PERMISSION_MASK as u64),
    protocol_two_only: 0x00,
};

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
    fields: stream::Fields<Status, Parameters>,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::new(),
            fields: stream::Fields::new(Parameters::new()),
        }
    }
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let fields = &mut self.fields;
        self.decoder.consume(bytes, &mut |event, offset| {
            fields.event(event, offset, PERMISSIONS)
        });
    }
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        memory.wipe(&mut self.fields.output.agreement);
        memory.wipe(&mut self.fields.output.auth);
        memory.wipe(&mut self.fields.output.new_pin);
        memory.wipe(&mut self.fields.output.pin_hash);
        memory.wipe(&mut self.fields.output.rp);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        self.fields.finish()?;
        if self.fields.output.subcommand == schema::Command::Retries as u8 {
            Ok(Command::GetPinRetries)
        } else if self.fields.output.subcommand == schema::Command::Agreement as u8 {
            Ok(Command::GetKeyAgreement)
        } else {
            Ok(Command::ClientPin(core::mem::replace(
                &mut self.fields.output,
                Parameters::new(),
            )))
        }
    }
}
impl stream::Output<Status> for Parameters {
    fn protocol(&self) -> u8 {
        self.protocol
    }
    fn subcommand(&self) -> u8 {
        self.subcommand
    }
    fn permissions(&self) -> u16 {
        u16::from(self.permissions)
    }
    fn rp_present(&self) -> bool {
        self.rp_len != 0
    }
    fn set_protocol(&mut self, value: u8) {
        self.protocol = value;
    }
    fn set_subcommand(&mut self, value: u8) {
        self.subcommand = value;
    }
    fn set_permissions(&mut self, value: u16) {
        self.permissions = value as u8;
    }
    fn agreement(&mut self) -> &mut [u8; 64] {
        &mut self.agreement
    }
    fn start(&mut self, label: i8, _offset: u16, length: u16) {
        if label == schema::LABEL_RP_ID {
            self.rp_len = usize::from(length);
        }
    }
    fn body(
        &mut self,
        event: &canokey_protocol::cbor::Event<'_>,
        body: &mut Option<(i8, usize)>,
    ) -> Result<(), Status> {
        let (label, _) = body.ok_or(Status::InvalidCbor)?;
        let target: &mut [u8] = match label {
            schema::LABEL_AUTH => &mut self.auth,
            schema::LABEL_NEW_PIN => &mut self.new_pin,
            schema::LABEL_PIN_HASH => &mut self.pin_hash,
            schema::LABEL_RP_ID => &mut self.rp,
            _ => return Err(Status::InvalidCbor),
        };
        canokey_ctap::request::stream::consume_cbor_body(event, body, target)
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod reference;

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
pub(super) mod admission_cases {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ctap/tests/fixtures/client_pin_admission.rs"
    ));
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn required_scope_matrix_matches_wire_status_at_every_fragment_boundary() {
        for (bytes, expected) in admission_cases::legacy_token_cases() {
            for split in 0..=bytes.len() {
                let mut parser = Parser::new();
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..]);
                assert_eq!(
                    parser.finish().err().map(|error| error as u8),
                    expected,
                    "split={split} bytes={bytes:?}"
                );
            }
        }
    }

    #[test]
    fn invalid_points_are_structural_fields_until_complete_request_admission() {
        for point in admission_cases::invalid_points() {
            for (bytes, expected) in admission_cases::legacy_token_cases_for_point(&point) {
                for split in 0..=bytes.len() {
                    let mut parser = Parser::new();
                    parser.consume(&bytes[..split]);
                    parser.consume(&bytes[split..]);
                    assert_eq!(
                        parser.finish().err().map(|error| error as u8),
                        expected,
                        "split={split} bytes={bytes:?}"
                    );
                }
            }
        }
    }

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

#[cfg(test)]
mod differential_tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn fingerprint(command: Command) -> Vec<u8> {
        match command {
            Command::GetPinRetries => std::vec![wire::V1],
            Command::GetKeyAgreement => std::vec![wire::V2],
            Command::ClientPin(p) => {
                let mut bytes = std::vec![p.protocol, p.subcommand, p.permissions];
                bytes.extend_from_slice(&(p.rp_len as u16).to_be_bytes());
                bytes.extend_from_slice(&p.agreement);
                bytes.extend_from_slice(&p.auth);
                bytes.extend_from_slice(&p.new_pin);
                bytes.extend_from_slice(&p.pin_hash);
                bytes.extend_from_slice(&p.rp);
                bytes
            }
            _ => panic!("ClientPIN command expected"),
        }
    }
    fn borrowed(bytes: &[u8]) -> Result<Vec<u8>, Status> {
        let parsed = schema::borrowed::decode::<Status, { (super::super::MAX_REQUEST - 1) as u16 }>(
            bytes,
            PERMISSIONS,
        )?;
        Ok(fingerprint(match parsed.command {
            schema::Command::Retries => Command::GetPinRetries,
            schema::Command::Agreement => Command::GetKeyAgreement,
            _ => {
                let mut p = Parameters::new();
                p.protocol = parsed.protocol;
                p.subcommand = parsed.command as u8;
                p.permissions = parsed.permissions as u8;
                p.agreement = parsed.agreement;
                p.auth[..parsed.auth.len()].copy_from_slice(parsed.auth);
                p.new_pin[..parsed.new_pin.len()].copy_from_slice(parsed.new_pin);
                p.pin_hash[..parsed.pin_hash.len()].copy_from_slice(parsed.pin_hash);
                if let Some(rp) = parsed.rp_id {
                    p.rp_len = rp.len();
                    p.rp[..rp.len()].copy_from_slice(rp.as_bytes());
                }
                Command::ClientPin(p)
            }
        }))
    }
    fn compare(bytes: &[u8], split: usize) {
        let mut reference = reference::Parser::new();
        reference.consume(&bytes[..split]);
        reference.consume(&bytes[split..]);
        let expected = reference.finish().map(fingerprint);
        let mut actual = Parser::new();
        actual.consume(&bytes[..split]);
        actual.consume(&bytes[split..]);
        assert_eq!(
            actual.finish().map(fingerprint),
            expected,
            "split={split} bytes={bytes:02x?}"
        );
        assert_eq!(borrowed(bytes), expected, "borrowed bytes={bytes:02x?}");
    }
    #[test]
    fn actual_owned_and_borrowed_match_pre_extraction_parser() {
        let mut count = 0;
        for (bytes, _) in admission_cases::parsing_cases() {
            for split in 0..=bytes.len() {
                compare(&bytes, split);
            }
            for end in 0..bytes.len() {
                compare(&bytes[..end], end / 2);
            }
            for index in 0..bytes.len() {
                for replacement in [0x00, 0x01, 0x17, 0x18, 0x20, 0x3f, 0x40, 0x50, 0x80, 0xff] {
                    let mut mutated = bytes.clone();
                    mutated[index] = replacement;
                    compare(&mutated, index);
                    count += 1;
                }
            }
        }
        std::println!("Actual ClientPIN pre-extraction oracle: {count} mutations");
    }
}
