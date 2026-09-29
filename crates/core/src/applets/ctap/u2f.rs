// SPDX-License-Identifier: Apache-2.0
//! CTAP1 APDUs. Inputs are owned before presence, storage or crypto runs.
use super::{Response, Session, credential, pin};
use crate::{
    ports::{KeyOperation, Platform, alg},
    runtime::workspace::Workspace,
};
use canokey_protocol::{apdu::Header, der::der_signature, response::StatusWord as Sw};

pub const MAX_INPUT: usize = 65 + credential::ID_BYTES;
pub struct Request {
    pub header: Header,
    pub data: [u8; MAX_INPUT],
    pub length: usize,
}
impl Request {
    pub fn new(header: Header) -> Self {
        Self {
            header,
            data: [0; MAX_INPUT],
            length: 0,
        }
    }
    pub fn consume(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(MAX_INPUT.saturating_sub(self.length));
        if n != 0 {
            self.data[self.length..self.length + n].copy_from_slice(&bytes[..n]);
        }
        self.length = self.length.saturating_add(bytes.len());
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.data);
        self.length = 0;
        self.header = Header {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
        };
    }
}

impl Session {
    pub(super) fn u2f(
        &mut self,
        request: &Request,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<Response, Sw> {
        self.assertion.remaining = 0;
        self.assertion.hmac.clear(p.memory);
        self.management = super::management::Cursor::new();
        self.abort_blob(p);
        let result = self.u2f_inner(request, w, p);
        p.memory.wipe(&mut w.key.bytes);
        if result.is_err() {
            w.clear(p.memory);
        }
        result
    }
    fn u2f_inner(
        &mut self,
        r: &Request,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<Response, Sw> {
        if r.header.cla != 0 {
            return Err(Sw::CLA_NOT_SUPPORTED);
        }
        match r.header.ins {
            3 => {
                return if r.length == 0 {
                    Ok(Response::Constant(b"U2F_V2"))
                } else {
                    Err(Sw::WRONG_LENGTH)
                };
            }
            0xa4 => return Ok(Response::Constant(b"U2F_V2")),
            0x10 => return Ok(Response::Constant(&[])),
            1 | 2 => (),
            _ => return Err(Sw::INS_NOT_SUPPORTED),
        }
        if pin::policy(p).map_err(|_| Sw::UNABLE_TO_PROCESS)?.flags & pin::ALWAYS_UV != 0 {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        let register = r.header.ins == 1;
        if register && r.length != 64 {
            return Err(Sw::WRONG_LENGTH);
        }
        if !register {
            if r.length != MAX_INPUT {
                return Err(Sw::WRONG_DATA);
            }
            if usize::from(r.data[64]) != credential::ID_BYTES {
                return Err(Sw::WRONG_LENGTH);
            }
        }
        let rp = r.data[32..64].try_into().unwrap();
        let mut id = [0; credential::ID_BYTES];
        if !register {
            id.copy_from_slice(&r.data[65..]);
            // U2F accepts only P-256 handles, whose derivation does not use
            // provisioned SM2 identifiers. Reject other algorithms before opening.
            if credential::algorithm(&id) != Ok(alg::P256) {
                return Err(Sw::WRONG_DATA);
            }
            credential::open(&id, self.sm2, rp, w.key, p).map_err(|_| Sw::WRONG_DATA)?;
            if r.header.p1 == 7 {
                return Err(Sw::CONDITIONS_NOT_SATISFIED);
            }
        }
        // CTAP1 hosts poll; this consumes a completed gesture without blocking.
        if !self.presence.poll(p.device) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let (message_len, prefix, certificate) = if register {
            id = credential::create(alg::P256, 1, self.sm2, rp, w.key, p)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            let n = p
                .crypto
                .key_operation(
                    KeyOperation::Public,
                    alg::P256,
                    &mut w.key,
                    &[],
                    &mut w.output[2..],
                )
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            if n != 64 {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            // Signed registration bytes: 00 || appId || challenge || handle || public key.
            w.input[0] = 0;
            w.input[1..33].copy_from_slice(rp);
            w.input[33..65].copy_from_slice(&r.data[..32]);
            w.input[65..65 + id.len()].copy_from_slice(&id);
            let public = 65 + id.len();
            w.input[public] = 4;
            w.input[public + 1..public + 65].copy_from_slice(&w.output[2..66]);
            // Registration response prefix is independent of the signed byte order.
            w.output[0] = 5;
            w.output[1] = 4;
            w.output[66] = id.len() as u8;
            w.output[67..67 + id.len()].copy_from_slice(&id);
            p.memory.wipe(&mut w.key.bytes);
            super::attestation::key((&mut w.key.bytes[..32]).try_into().unwrap(), p)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            let cert = super::attestation::certificate(p).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            (public + 65, 67 + id.len(), Some(cert))
        } else {
            w.input[..32].copy_from_slice(rp);
            w.input[32] = 1;
            w.input[33..37].copy_from_slice(
                &credential::counter(p).map_err(|_| Sw::CONDITIONS_NOT_SATISFIED)?,
            );
            w.input[37..69].copy_from_slice(&r.data[..32]);
            w.output[..5].copy_from_slice(&w.input[32..37]);
            (69, 5, None)
        };
        let mut digest = [0; 32];
        p.crypto
            .sha256(&w.input[..message_len], &mut digest)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        p.crypto
            .p256_sign(
                (&w.key.bytes[..32]).try_into().unwrap(),
                &digest,
                (&mut w.output[prefix..prefix + 64]).try_into().unwrap(),
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        let n = der_signature(&mut w.output[prefix..], 64).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        Ok(if let Some(length) = certificate {
            Response::Authentication {
                prefix,
                auth: 0,
                certificate: Some((prefix, length)),
                total: prefix + n + length,
            }
        } else {
            Response::Prepared(prefix + n)
        })
    }
}
