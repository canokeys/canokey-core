// SPDX-License-Identifier: Apache-2.0
//! Borrowed ClientPIN output driven by the same field and framing state machines.
use super::{
    Command, PermissionPolicy,
    stream::{Error, Fields, Output},
};
use crate::{client_pin::agreement::POINT_BYTES, request::stream::Decoder};

#[derive(Clone, Copy, Default)]
struct Span {
    start: u16,
    length: u16,
}
impl Span {
    fn bytes(self, input: &[u8]) -> &[u8] {
        &input[usize::from(self.start)..usize::from(self.start) + usize::from(self.length)]
    }
}
struct Backing {
    protocol: u8,
    subcommand: u8,
    permissions: u16,
    agreement: [u8; POINT_BYTES],
    spans: [Span; 4], // pinUvAuthParam, newPinEnc, pinHashEnc, rpId.
}
impl Default for Backing {
    fn default() -> Self {
        Self {
            protocol: 0x00,
            subcommand: 0x00,
            permissions: 0x0000,
            agreement: [0x00; POINT_BYTES],
            spans: [Span::default(); 4],
        }
    }
}
impl<E: Error> Output<E> for Backing {
    fn protocol(&self) -> u8 {
        self.protocol
    }
    fn subcommand(&self) -> u8 {
        self.subcommand
    }
    fn permissions(&self) -> u16 {
        self.permissions
    }
    fn rp_present(&self) -> bool {
        self.spans[3].length != 0
    }
    fn set_protocol(&mut self, value: u8) {
        self.protocol = value;
    }
    fn set_subcommand(&mut self, value: u8) {
        self.subcommand = value;
    }
    fn set_permissions(&mut self, value: u16) {
        self.permissions = value;
    }
    fn agreement(&mut self) -> &mut [u8; POINT_BYTES] {
        &mut self.agreement
    }
    fn start(&mut self, label: i8, offset: u16, length: u16) {
        let index = if label == super::LABEL_RP_ID {
            3
        } else {
            (label - super::LABEL_AUTH) as usize
        };
        self.spans[index] = Span {
            start: offset,
            length,
        };
    }
    fn body(
        &mut self,
        event: &canokey_protocol::cbor::Event<'_>,
        body: &mut Option<(i8, usize)>,
    ) -> Result<(), E> {
        // Decoder owns framing and bounds. Borrowed fields require no body
        // copy; the header span is valid only after decoder.finish succeeds.
        match event {
            canokey_protocol::cbor::Event::Data(_) => Ok(()),
            canokey_protocol::cbor::Event::End => {
                *body = None;
                Ok(())
            }
            _ => Err(E::INVALID_CBOR),
        }
    }
}
pub struct Request<'a> {
    pub command: Command,
    pub protocol: u8,
    pub permissions: u16,
    pub agreement: [u8; POINT_BYTES],
    pub auth: &'a [u8],
    pub new_pin: &'a [u8],
    pub pin_hash: &'a [u8],
    pub rp_id: Option<&'a str>,
}
/// Encrypted fields and RP text point into the original request. Only the
/// structurally admitted coordinates are copied; peer validation remains crypto.
pub fn decode<E: Error, const LIMIT: u16>(
    input: &[u8],
    permissions: PermissionPolicy,
) -> Result<Request<'_>, E> {
    let mut decoder = Decoder::<E, LIMIT>::new();
    let mut fields = Fields::new(Backing::default());
    decoder.consume(input, &mut |event, offset| {
        fields.event(event, offset, permissions)
    });
    decoder.finish()?;
    let command = fields.finish()?;
    let backing = fields.output;
    let [auth, new_pin, pin_hash, rp] = backing.spans;
    Ok(Request {
        command,
        protocol: backing.protocol,
        permissions: backing.permissions,
        agreement: backing.agreement,
        auth: auth.bytes(input),
        new_pin: new_pin.bytes(input),
        pin_hash: pin_hash.bytes(input),
        // Decoder has already validated UTF-8 and the nonempty RP bound.
        rp_id: (rp.length != 0).then(|| core::str::from_utf8(rp.bytes(input)).unwrap()),
    })
}
