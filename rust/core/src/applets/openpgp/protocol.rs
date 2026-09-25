// SPDX-License-Identifier: Apache-2.0
//! OpenPGP Card 3.4 adapter. The runtime owns chaining and response position.

use super::domain::{grant, key_role};
use super::{
    encoding::BufferRange,
    wire::{ins::*, limits, reference, tag},
};
use super::{
    import::Import,
    pin,
    repository::{self as repo, CERTS, io},
};
use crate::{
    Platform,
    ports::{KeyOperation, Record},
    runtime::workspace::Workspace,
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
pub const AID: &[u8] = &[0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
enum Request {
    None,
    Buffered,
    Certificate,
    Import,
}
#[derive(Clone, Copy)]
enum Response {
    Memory,
    Certificate(usize),
}
pub struct OpenPgp {
    pub(super) session: super::service::Session,
    occurrence: usize,
    request: Request,
    response: Response,
    pub(super) used: usize,
    import: Import,
}
impl Default for OpenPgp {
    fn default() -> Self {
        Self::new()
    }
}
impl OpenPgp {
    pub const fn new() -> Self {
        Self {
            session: super::service::Session::new(),
            occurrence: 0,
            request: Request::None,
            response: Response::Memory,
            used: 0,
            import: Import::new(),
        }
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        repo::install(p).map_err(Into::into)
    }
    pub fn reset(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        self.abort(w, p);
        self.session.grants = 0;
        self.occurrence = 0;
        self.session.clear_touch();
        self.response = Response::Memory;
    }
    pub fn clear(&mut self, w: &mut Workspace, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.reset(w, p);
        repo::reset(p).map_err(Into::into)
    }
    pub fn select(&mut self, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.occurrence = 0;
        let terminated = repo::terminated(p)?;
        if terminated {
            return Err(Sw::SELECTED_FILE_TERMINATED);
        }
        Ok(0)
    }
    pub fn limit(h: Header) -> u32 {
        // P1/P2 together identify the data object for PUT DATA. Only key
        // imports and certificates use streaming consumers with larger limits;
        // ordinary commands must fit the bounded input workspace.
        let object_tag = u16::from_be_bytes([h.p1, h.p2]);
        u32::from(match (h.ins, object_tag) {
            // Includes the RSA private components and their import envelope.
            (IMPORT_KEY, _) => limits::KEY_IMPORT_BYTES,
            // DO 7F21 is the cardholder certificate, not a key-import template.
            (PUT_DATA, tag::CERTIFICATE) => limits::CERTIFICATE_BYTES,
            // Covers a full RSA-4096 ciphertext plus its padding indicator.
            _ => limits::ORDINARY_COMMAND_BYTES,
        })
    }
    pub(super) fn admin(&self) -> Result<(), Sw> {
        self.session.admin().map_err(Into::into)
    }
    pub fn begin(&mut self, h: Header, w: &mut Workspace, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.used = 0;
        w.clear(p.memory);
        self.response = Response::Memory;
        let terminated = repo::terminated(p)?;
        if terminated && h.ins != ACTIVATE {
            return Err(Sw::SELECTED_FILE_TERMINATED);
        }
        self.request = match h.ins {
            PUT_DATA if u16::from_be_bytes([h.p1, h.p2]) == tag::CERTIFICATE => {
                self.admin()?;
                if self.occurrence >= key_role::COUNT {
                    return Err(Sw::REFERENCE_NOT_FOUND);
                }
                p.storage.stage_begin().map_err(io)?;
                Request::Certificate
            }
            IMPORT_KEY => {
                self.admin()?;
                // IMPORT uses the fixed PUT DATA selector 3FFF. The target
                // key role is inside the 4D body, not in P1/P2.
                if h.p1 != 0x3f || h.p2 != 0xff {
                    return Err(Sw::WRONG_P1P2);
                }
                self.import = Import::new();
                Request::Import
            }
            _ => Request::Buffered,
        };
        Ok(())
    }
    pub fn consume(&mut self, b: &[u8], w: &mut Workspace, p: &mut Platform<'_>) -> Result<(), Sw> {
        match self.request {
            Request::Buffered => {
                let end = self.used.checked_add(b.len()).ok_or(Sw::WRONG_LENGTH)?;
                w.input
                    .get_mut(self.used..end)
                    .ok_or(Sw::WRONG_LENGTH)?
                    .copy_from_slice(b);
            }
            Request::Certificate => p.storage.stage_append(b).map_err(io)?,
            Request::Import => self.import.feed(b, &mut w.key.bytes, p)?,
            Request::None => return Err(Sw::COMMAND_NOT_ALLOWED),
        }
        self.used += b.len();
        Ok(())
    }
    pub fn abort(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        if matches!(self.request, Request::Certificate) {
            p.storage.stage_abort();
        }
        self.request = Request::None;
        self.used = 0;
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(&mut w.input);
        self.import = Import::new();
    }
    pub fn close(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        p.memory.wipe(&mut w.output);
        self.response = Response::Memory;
    }
    #[cfg(feature = "pass")]
    pub fn take_presence(&mut self) -> bool {
        self.session.presence.take()
    }
    pub fn read(
        &self,
        offset: usize,
        out: &mut [u8],
        w: &Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        match self.response {
            Response::Memory => {
                let range = BufferRange::new(offset, out.len()).ok_or(Sw::UNABLE_TO_PROCESS)?;
                out.copy_from_slice(w.output.get(range.range()).ok_or(Sw::UNABLE_TO_PROCESS)?);
            }
            Response::Certificate(i) => p
                .storage
                .read_at(CERTS[i], offset as u32, out)
                .map_err(io)?,
        }
        Ok(out.len())
    }
    #[inline(never)]
    pub fn finish(
        &mut self,
        h: Header,
        le: u32,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        let result = match self.request {
            Request::Certificate => {
                let r = p
                    .storage
                    .stage_commit(CERTS[self.occurrence])
                    .map_err(|e| Sw::from(io(e)));
                if r.is_err() {
                    p.storage.stage_abort()
                }
                self.occurrence = 0;
                r.map(|_| 0)
            }
            Request::Import => (|| {
                self.import.finish(&mut w.key.bytes)?;
                let a = self.import.algorithm;
                p.crypto
                    .key_operation(KeyOperation::Validate, a.0, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::WRONG_DATA)?;
                repo::save_key(p, self.import.role, 2, &w.key.bytes)?;
                Ok(0)
            })(),
            Request::Buffered => self.command(h, le, w, p),
            Request::None => Err(Sw::COMMAND_NOT_ALLOWED),
        };
        self.request = Request::None;
        self.used = 0;
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(&mut w.input);
        self.import = Import::new();
        if result.is_err() {
            self.close(w, p)
        }
        // The runtime finish adapter carries the response status alongside
        // the byte count for all applets; OpenPGP commits are the successful
        // case here, while failures leave through the Err status above.
        result.map(|n| (n, Sw::SUCCESS))
    }
    fn command(
        &mut self,
        h: Header,
        le: u32,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let b = &w.input[..self.used];
        let tag = u16::from_be_bytes([h.p1, h.p2]);
        match h.ins {
            VERIFY => {
                // P2 selects a password grant (81 signature PW1, 82 other
                // PW1, 83 admin PW3). P1=00 verifies/queries; FF logs out.
                let bit = match h.p2 {
                    reference::PW1_SIGNATURE => grant::SIGNATURE,
                    reference::PW1_OTHER => grant::OTHER,
                    reference::PW3 => grant::ADMIN,
                    _ => return Err(Sw::WRONG_P1P2),
                };
                let id = if bit == grant::ADMIN {
                    Record::PgpPw3
                } else {
                    Record::PgpPw1
                };
                if h.p1 == 0xff && b.is_empty() {
                    self.session.grants &= !bit;
                    return Ok(0);
                }
                if h.p1 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                if b.is_empty() {
                    return if self.session.grants & bit != 0 {
                        Ok(0)
                    } else {
                        Err(Sw::retries(pin::info(id, p)?.retries_remaining))
                    };
                }
                self.session.verify_pin(bit, b, p)?;
                Ok(0)
            }
            CHANGE_REFERENCE_DATA => {
                // P1=00 changes the secret selected by P2 (81 PW1 / 83 PW3);
                // data contains the old secret followed by the new one.
                if h.p1 != 0x00 || !matches!(h.p2, reference::PW1_SIGNATURE | reference::PW3) {
                    return Err(Sw::WRONG_P1P2);
                }
                let id = if h.p2 == reference::PW1_SIGNATURE {
                    Record::PgpPw1
                } else {
                    Record::PgpPw3
                };
                self.session.change_pin(id, b, p)?;
                Ok(0)
            }
            RESET_RETRY_COUNTER => {
                // P2=81 always targets PW1. P1=00 supplies reset-code + new
                // PW1; P1=02 uses an existing PW3 grant and supplies only PW1.
                if h.p2 != reference::PW1_SIGNATURE || !matches!(h.p1, 0x00 | 0x02) {
                    return Err(Sw::WRONG_P1P2);
                }
                self.session.reset_pw1(h.p1 == 0x02, b, p)?;
                Ok(0)
            }
            SELECT_DATA => {
                // P1 selects certificate occurrence 0/1/2 (SIG/DEC/AUT).
                // P2=04 selects by the tag list in the 60 template below;
                // this profile permits only the certificate DO 7F21.
                if h.p1 > 0x02 || h.p2 != 0x04 {
                    return Err(Sw::WRONG_P1P2);
                }
                if b != [0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21] {
                    return Err(Sw::WRONG_DATA);
                }
                self.occurrence = h.p1 as usize;
                Ok(0)
            }
            GET_DATA | GET_NEXT_DATA => {
                if !b.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.ins == GET_NEXT_DATA {
                    if tag != tag::CERTIFICATE {
                        return Err(Sw::WRONG_P1P2);
                    }
                    self.occurrence += 1;
                }
                if tag == tag::CERTIFICATE {
                    if self.occurrence >= key_role::COUNT {
                        return Err(Sw::REFERENCE_NOT_FOUND);
                    }
                    let n = p.storage.size(CERTS[self.occurrence]).map_err(io)?;
                    self.response = Response::Certificate(self.occurrence);
                    return Ok(n);
                }
                self.get(tag, &mut w.output, p).map(|n| n as u32)
            }
            PUT_DATA => {
                self.admin()?;
                self.put(tag, b, p)?;
                Ok(0)
            }
            GENERATE_KEY => self.generate_key(h, w, p),
            INTERNAL_AUTHENTICATE | PERFORM_SECURITY_OPERATION => self.use_key(h, w, p),
            GET_CHALLENGE => {
                // P1/P2=0000 and empty body: Le alone requests 1..256 random bytes.
                if tag != 0x0000 {
                    return Err(Sw::WRONG_P1P2);
                }
                if !b.is_empty() || le == 0 || le > 256 {
                    return Err(Sw::WRONG_LENGTH);
                }
                p.crypto
                    .random(&mut w.output[..le as usize])
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                Ok(le)
            }
            TERMINATE => {
                // E6 00 00 marks the application terminated without erasing it.
                // Require PW3 authorization unless PW3 is already blocked,
                // allowing recovery through a subsequent ACTIVATE command.
                if tag != 0x0000 || !b.is_empty() {
                    return Err(Sw::WRONG_P1P2);
                }
                if pin::info(Record::PgpPw3, p)?.retries_remaining != 0 {
                    self.admin()?;
                }
                p.storage
                    .replace_at(Record::PgpState, 1, &[1])
                    .map_err(io)?;
                self.session.grants = 0;
                self.session.clear_touch();
                Ok(0)
            }
            ACTIVATE => {
                // 44 00 00 reinitializes a terminated applet; on an active
                // applet it succeeds without resetting credentials or keys.
                if tag != 0x0000 || !b.is_empty() {
                    return Err(Sw::WRONG_P1P2);
                }
                if repo::terminated(p)? {
                    self.clear(w, p)?;
                }
                Ok(0)
            }
            SET_RETRIES => {
                // CanoKey F2 00 00: body contains PW1, reset-code and PW3 retry
                // limits (1..15), in that order. PW1/PW3 return to default
                // values; reset-code value is retained. Requires a PW3 grant.
                self.admin()?;
                if tag != 0x0000 {
                    return Err(Sw::WRONG_P1P2);
                }
                if b.len() != 3 || b.iter().any(|v| *v == 0 || *v > 15) {
                    return Err(Sw::WRONG_DATA);
                }
                self.session.grants = 0;
                pin::create(Record::PgpPw1, b"123456", b[0], p)?;
                pin::retry_limit(Record::PgpRc, b[1], p)?;
                pin::create(Record::PgpPw3, b"12345678", b[2], p)?;
                Ok(0)
            }
            _ => Err(Sw::INS_NOT_SUPPORTED),
        }
    }
}

impl From<super::domain::Error> for Sw {
    // Keep a single status table across data, key and orchestration paths.
    #[inline(never)]
    fn from(error: super::domain::Error) -> Self {
        use super::domain::Error;
        match error {
            Error::Storage | Error::Crypto => Sw::UNABLE_TO_PROCESS,
            Error::Length => Sw::WRONG_LENGTH,
            Error::Blocked => Sw::AUTHENTICATION_BLOCKED,
            Error::Unauthorized => Sw::SECURITY_STATUS_NOT_SATISFIED,
            Error::Missing => Sw::REFERENCE_NOT_FOUND,
            // Rust core reports a cancelled/expired gesture as execution
            // error (0x6400); this is the documented Rust profile mapping.
            Error::Presence => Sw::EXECUTION_ERROR,
        }
    }
}
