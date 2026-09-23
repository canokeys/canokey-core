// SPDX-License-Identifier: Apache-2.0
//! OpenPGP Card 3.4 adapter. The runtime owns chaining and response position.
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
pub const AID: &[u8] = &[0xd2, 0x76, 0, 1, 0x24, 1];
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
            return Err(Sw(0x6285));
        }
        Ok(0)
    }
    pub fn limit(h: Header) -> u32 {
        match (h.ins, h.p1, h.p2) {
            (0xdb, _, _) => 1400,
            (0xda, 0x7f, 0x21) => 1152,
            _ => 513,
        }
    }
    pub(super) fn admin(&self) -> Result<(), Sw> {
        self.session.admin().map_err(Into::into)
    }
    pub fn begin(&mut self, h: Header, w: &mut Workspace, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.used = 0;
        w.clear(p.memory);
        self.response = Response::Memory;
        let terminated = repo::terminated(p)?;
        if terminated && h.ins != 0x44 {
            return Err(Sw(0x6285));
        }
        self.request = match h.ins {
            0xda if h.p1 == 0x7f && h.p2 == 0x21 => {
                self.admin()?;
                if self.occurrence >= 3 {
                    return Err(Sw(0x6a88));
                }
                p.storage.stage_begin().map_err(io)?;
                Request::Certificate
            }
            0xdb => {
                self.admin()?;
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
            Response::Memory => out.copy_from_slice(
                w.output
                    .get(offset..offset + out.len())
                    .ok_or(Sw::UNABLE_TO_PROCESS)?,
            ),
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
            0x20 => {
                let bit = match h.p2 {
                    0x81 => 1,
                    0x82 => 2,
                    0x83 => 4,
                    _ => return Err(Sw::WRONG_P1P2),
                };
                let id = if bit == 4 {
                    Record::PgpPw3
                } else {
                    Record::PgpPw1
                };
                if h.p1 == 0xff && b.is_empty() {
                    self.session.grants &= !bit;
                    return Ok(0);
                }
                if h.p1 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if b.is_empty() {
                    return if self.session.grants & bit != 0 {
                        Ok(0)
                    } else {
                        Err(Sw(0x63c0 | pin::info(id, p)?.1 as u16))
                    };
                }
                self.session.verify_pin(bit, b, p)?;
                Ok(0)
            }
            0x24 => {
                if h.p1 != 0 || !matches!(h.p2, 0x81 | 0x83) {
                    return Err(Sw::WRONG_P1P2);
                }
                let id = if h.p2 == 0x81 {
                    Record::PgpPw1
                } else {
                    Record::PgpPw3
                };
                self.session.change_pin(id, b, p)?;
                Ok(0)
            }
            0x2c => {
                if h.p2 != 0x81 || !matches!(h.p1, 0 | 2) {
                    return Err(Sw::WRONG_P1P2);
                }
                self.session.reset_pw1(h.p1 == 2, b, p)?;
                Ok(0)
            }
            0xa5 => {
                if h.p1 > 2 || h.p2 != 4 {
                    return Err(Sw::WRONG_P1P2);
                }
                if b != [0x60, 4, 0x5c, 2, 0x7f, 0x21] {
                    return Err(Sw::WRONG_DATA);
                }
                self.occurrence = h.p1 as usize;
                Ok(0)
            }
            0xca | 0xcc => {
                if !b.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.ins == 0xcc {
                    if tag != 0x7f21 {
                        return Err(Sw::WRONG_P1P2);
                    }
                    self.occurrence += 1;
                }
                if tag == 0x7f21 {
                    if self.occurrence >= 3 {
                        return Err(Sw(0x6a88));
                    }
                    let n = p.storage.size(CERTS[self.occurrence]).map_err(io)?;
                    self.response = Response::Certificate(self.occurrence);
                    return Ok(n);
                }
                self.get(tag, &mut w.output, p).map(|n| n as u32)
            }
            0xda => {
                self.admin()?;
                self.put(tag, b, p)?;
                Ok(0)
            }
            0x47 => self.generate_key(h, w, p),
            0x88 | 0x2a => self.use_key(h, w, p),
            0x84 => {
                if tag != 0 {
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
            0xe6 => {
                if tag != 0 || !b.is_empty() {
                    return Err(Sw::WRONG_P1P2);
                }
                if pin::info(Record::PgpPw3, p)?.1 != 0 {
                    self.admin()?;
                }
                p.storage
                    .replace_at(Record::PgpState, 1, &[1])
                    .map_err(io)?;
                self.session.grants = 0;
                self.session.clear_touch();
                Ok(0)
            }
            0x44 => {
                if tag != 0 || !b.is_empty() {
                    return Err(Sw::WRONG_P1P2);
                }
                if repo::terminated(p)? {
                    self.clear(w, p)?;
                }
                Ok(0)
            }
            0xf2 => {
                self.admin()?;
                if tag != 0 {
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
    fn from(error: super::domain::Error) -> Self {
        use super::domain::Error;
        match error {
            Error::Storage => Sw::UNABLE_TO_PROCESS,
            Error::Length => Sw::WRONG_LENGTH,
            Error::Blocked => Sw::AUTHENTICATION_BLOCKED,
            Error::Unauthorized => Sw::SECURITY_STATUS_NOT_SATISFIED,
            Error::Missing => Sw(0x6a88),
            Error::Invalid => Sw::WRONG_DATA,
            Error::Presence => Sw(0x6400),
        }
    }
}
