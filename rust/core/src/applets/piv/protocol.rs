// SPDX-License-Identifier: Apache-2.0
//! Independent PIV adapter. APDU lifecycle and byte cursors belong to the runtime.
use super::{codec, ga::Ga, import::Import, pin::Pins, repository as repo};
mod keys;
mod management;
mod metadata;
mod objects;
mod provision;
mod stream;
use crate::{
    Platform,
    ports::{KeyOperation, Record, StorageError},
    runtime::{presence, workspace::Workspace},
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
use objects::Put;
pub const AID: &[u8] = &[0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0];
pub const CAPACITY: usize = 513;
include!(concat!(env!("OUT_DIR"), "/piv_version.rs"));
const SELECT: &[u8] = &[
    0x61, 0x11, 0x4f, 6, 0, 0, 0x10, 0, 1, 0, 0x79, 7, 0x4f, 5, 0xa0, 0, 0, 3, 8,
];
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    External,
    Mutual,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamPhase {
    Identity,
    ResponseTag,
    Payload,
}
enum Request {
    None,
    Buffered,
    Ga,
    Stream(u8),
    Import,
    Put,
}
#[derive(Clone, Copy)]
enum Response {
    Memory,
    Object(usize),
    Crypto(u8),
}
pub struct Piv {
    pub(super) pins: Pins,
    admin: bool,
    consumed: bool,
    auth_mode: AuthMode,
    challenge: [u8; 16],
    config: [u8; 10],
    request: Request,
    response: Response,
    used: usize,
    header: [u8; 32],
    header_len: usize,
    body_len: usize,
    suffix: [u8; 6],
    suffix_len: usize,
    import: Import,
    ga: Ga,
    put: Put,
    last_touch: Option<u32>,
    pub presence: presence::Request,
    pending_public: Option<(usize, bool)>,
    agreement: Option<usize>,
    stream_phase: StreamPhase,
    sm2_id: [u8; 32],
    sm2_id_used: usize,
}
impl Piv {
    pub const fn new() -> Self {
        Self {
            pins: Pins::new(),
            admin: false,
            consumed: false,
            auth_mode: AuthMode::None,
            challenge: [0; 16],
            config: repo::DEFAULT_CONFIG,
            request: Request::None,
            response: Response::Memory,
            used: 0,
            header: [0; 32],
            header_len: 0,
            body_len: 0,
            suffix: [0; 6],
            suffix_len: 0,
            import: Import::new(),
            ga: Ga::new(),
            put: Put::new(),
            last_touch: None,
            presence: presence::Request::new(),
            pending_public: None,
            agreement: None,
            stream_phase: StreamPhase::Identity,
            sm2_id: [0; 32],
            sm2_id_used: 0,
        }
    }
    fn reset_classic(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        self.agreement = None;
        p.memory.wipe(&mut w.agreement);
        self.pins.reset();
        self.admin = false;
        self.consumed = false;
        self.last_touch = None;
        self.auth_clear(p);
        self.cancel_classic(w, p);
        self.close_classic(w, p);
    }
    fn auth_clear(&mut self, p: &mut Platform<'_>) {
        self.auth_mode = AuthMode::None;
        p.memory.wipe(&mut self.challenge);
    }
    fn select_classic(&mut self, w: &mut Workspace, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.agreement = None;
        p.memory.wipe(&mut w.agreement);
        self.auth_clear(p);
        w.output[..SELECT.len()].copy_from_slice(SELECT);
        self.memory(SELECT.len());
        Ok(SELECT.len() as u32)
    }
    pub fn limit(h: Header) -> u32 {
        match h.ins {
            0xdb => 6573,
            0xfe => 1400,
            0x87 => 65535,
            _ => CAPACITY as u32,
        }
    }
    fn cancel_classic(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        if matches!(self.request, Request::Put) {
            p.storage.stage_abort()
        }
        self.agreement = None;
        p.memory.wipe(&mut w.agreement);
        self.pending_public = None;
        self.request = Request::None;
        self.import = Import::new();
        self.used = 0;
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(&mut w.input);
    }
    fn begin_classic(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.used = 0;
        self.memory(0);
        if h.ins == 0x87 && repo::algorithm(h.p1, &self.config) == Ok(9) && self.agreement.is_some()
        {
            p.memory.wipe(&mut w.key.bytes);
            p.memory.wipe(&mut w.input);
            p.memory.wipe(&mut w.output);
        } else {
            w.clear(p.memory);
            self.agreement = None;
        }
        if h.ins == 0xf5 && h.chained() {
            return Err(Sw::WRONG_LENGTH);
        }
        if h.ins != 0x87 {
            self.auth_clear(p)
        }
        self.request = match h.ins {
            0x87 => {
                self.ga = Ga::new();
                Request::Ga
            }
            0xfe => {
                self.authorized()?;
                let id = repo::slot(h.p2)?;
                let a = repo::algorithm(h.p1, &self.config).map_err(|_| Sw::WRONG_P1P2)?;
                if id == 24 && a != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                self.import = Import::new();
                self.import.meta = repo::meta(id, p)?;
                self.import.meta[repo::ALGORITHM] = a;
                self.import.meta[repo::ORIGIN] = 2;
                self.import.meta[repo::NAME_LENGTH..].fill(0);
                self.import.slot = id;
                Request::Import
            }
            0xdb => {
                self.authorized()?;
                if h.p1 != 0x3f || h.p2 != 0xff {
                    return Err(Sw::WRONG_P1P2);
                }
                self.put = Put::new();
                p.storage.stage_begin().map_err(repo::io)?;
                Request::Put
            }
            _ => Request::Buffered,
        };
        Ok(())
    }
    fn consume_classic(
        &mut self,
        b: &[u8],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        match self.request {
            Request::Ga => {
                self.ga.feed(b, &mut w.input)?;
                self.used = self.ga.used;
            }
            Request::Buffered => {
                let end = self.used.checked_add(b.len()).ok_or(Sw::WRONG_LENGTH)?;
                w.input
                    .get_mut(self.used..end)
                    .ok_or(Sw::WRONG_LENGTH)?
                    .copy_from_slice(b);
                self.used = end;
            }
            Request::Import => {
                self.import.feed(b, &mut w.key.bytes)?;
                self.used += b.len();
            }
            Request::Put => self.put.feed(b, p)?,
            Request::None | Request::Stream(_) => return Err(Sw::COMMAND_NOT_ALLOWED),
        }
        Ok(())
    }
    #[inline(never)]
    fn finish_classic(
        &mut self,
        h: Header,
        le: u32,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        let r = match self.request {
            Request::Ga => self
                .ga
                .finish()
                .and_then(|()| self.general_authenticate(h, w, p)),
            Request::Buffered => self.command(h, le, w, p),
            Request::Import => (|| {
                self.import.finish(&mut w.key.bytes)?;
                if self.import.meta[repo::ALGORITHM] < 10 {
                    p.crypto
                        .key_operation(
                            KeyOperation::Validate,
                            self.import.meta[repo::ALGORITHM],
                            &mut w.key,
                            &[],
                            &mut w.output,
                        )
                        .map_err(|_| Sw::WRONG_DATA)?;
                }
                repo::save(self.import.slot, &self.import.meta, &w.key.bytes, p)?;
                Ok(0)
            })(),
            Request::Put => self.put.finish(p),
            Request::None | Request::Stream(_) => Err(Sw::COMMAND_NOT_ALLOWED),
        };
        if r.is_err() {
            self.agreement = None;
            p.memory.wipe(&mut w.agreement);
            if matches!(self.request, Request::Put) {
                p.storage.stage_abort()
            }
            self.auth_clear(p);
            self.close_classic(w, p);
        }
        self.request = Request::None;
        self.import = Import::new();
        self.used = 0;
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(&mut w.input);
        r.map(|n| (n, Sw::SUCCESS))
    }
    fn memory(&mut self, n: usize) {
        self.response = Response::Memory;
        self.header_len = 0;
        self.suffix_len = 0;
        self.body_len = n;
    }
    fn authorized(&self) -> Result<(), Sw> {
        if self.admin {
            Ok(())
        } else {
            Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
        }
    }
    fn authorize_private(&mut self, pin_policy: u8) -> Result<(), Sw> {
        if pin_policy != 1 && (!self.pins.state.pin_ok || (pin_policy == 3 && self.consumed)) {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        self.consumed = true;
        Ok(())
    }
    fn touch(&mut self, policy: u8, p: &mut Platform<'_>) -> Result<(), Sw> {
        if policy < 2 {
            return Ok(());
        }
        let now = p.device.now();
        if policy == 3 && self.last_touch.is_some_and(|t| now.wrapping_sub(t) < 15000) {
            return Ok(());
        }
        if !self.presence.wait(p.device) {
            return Err(Sw(0x6400));
        }
        self.last_touch = Some(p.device.now());
        Ok(())
    }
    // Keep buffered-command temporaries out of the private-operation call path.
    #[inline(never)]
    fn command(
        &mut self,
        h: Header,
        le: u32,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        match h.ins {
            0x20 => {
                let r = self.pins.verify(h, &w.input[..self.used], p);
                if r.is_ok() && (self.used == 8 || h.p1 == 0xff) {
                    self.consumed = false;
                }
                r
            }
            0x24 => self.pins.change(h, &w.input[..self.used], p),
            0x2c => self.pins.reset_retry(h, &w.input[..self.used], p),
            0x84 | 0xfd | 0xf8 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                let n = match h.ins {
                    0x84 => {
                        if le == 0 || le > 256 {
                            return Err(Sw::WRONG_LENGTH);
                        }
                        p.crypto
                            .random(&mut w.output[..le as usize])
                            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                        le as usize
                    }
                    0xfd => {
                        w.output[..3].copy_from_slice(&PIV_VERSION);
                        3
                    }
                    _ => {
                        p.device.serial((&mut w.output[..4]).try_into().unwrap());
                        4
                    }
                };
                self.memory(n);
                Ok(n as u32)
            }
            0xcb => self.get(h, w, p),
            0x87 => self.general_authenticate(h, w, p),
            0x47 => self.generate(h, w, p),
            0xf7 => self.metadata(h, w, p),
            0xf5 => self.name(h, w, p),
            0xf6 => self.move_key(h, p),
            0xff => {
                if h.p1 != 0xff || !matches!(h.p2, 0xfe | 0xff) {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 27 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if w.input[..3] != [8, 0x9b, 24] {
                    return Err(Sw::WRONG_DATA);
                }
                self.authorized()?;
                let mut m = [0; 26];
                m[0] = 1;
                m[1] = if h.p2 == 0xfe { 2 } else { 1 };
                m[2..].copy_from_slice(&w.input[3..27]);
                let r = p
                    .storage
                    .replace(Record::PivManagement, &m)
                    .map_err(repo::io);
                p.memory.wipe(&mut m);
                if r.is_err() {
                    self.admin = false;
                }
                r.map(|_| 0)
            }
            0xfa => {
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if !(1..=15).contains(&h.p1) || !(1..=15).contains(&h.p2) {
                    return Err(Sw::WRONG_P1P2);
                }
                self.authorized()?;
                if !self.pins.state.pin_ok {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.admin = false;
                self.pins.defaults(h.p1, h.p2, p)?;
                Ok(0)
            }
            0xfb => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                self.pins.ready()?;
                if self.pins.state.pin_tries != 0 || self.pins.state.puk_tries != 0 {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.admin = false;
                self.pins.reset();
                self.last_touch = None;
                self.reset_persistent(p)?;
                Ok(0)
            }
            0xee => {
                if h.p2 != 0 || !matches!(h.p1, 1 | 2) {
                    return Err(Sw::WRONG_P1P2);
                }
                if h.p1 == 1 {
                    w.output[..10].copy_from_slice(&self.config);
                    self.memory(10);
                    Ok(10)
                } else {
                    self.authorized()?;
                    if self.used != 10 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    let c: &[u8; 10] = (&w.input[..10]).try_into().unwrap();
                    if !repo::config_valid(c) {
                        return Err(Sw::WRONG_DATA);
                    }
                    p.storage.replace(Record::PivConfig, c).map_err(repo::io)?;
                    self.config = *c;
                    Ok(0)
                }
            }
            _ => Err(Sw::INS_NOT_SUPPORTED),
        }
    }
    fn wrapped(&mut self, n: usize) -> Result<u32, Sw> {
        self.memory(n);
        let inner = if n < 128 {
            2
        } else if n < 256 {
            3
        } else {
            4
        };
        let a = codec::header(&mut self.header, &[0x7c], n + inner)?;
        self.header_len = a + codec::header(&mut self.header[a..], &[0x82], n)?;
        Ok((n + self.header_len) as u32)
    }
    fn read_classic(
        &self,
        offset: usize,
        out: &mut [u8],
        w: &Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.header_len + self.body_len + self.suffix_len)
        {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        match self.response {
            Response::Crypto(_) => return Err(Sw::UNABLE_TO_PROCESS),
            Response::Object(i) => p
                .storage
                .read_at(repo::OBJECTS[i], offset as u32, out)
                .map_err(repo::io)?,
            Response::Memory => {
                for (i, b) in out.iter_mut().enumerate() {
                    let at = offset + i;
                    *b = if at < self.header_len {
                        self.header[at]
                    } else if at < self.header_len + self.body_len {
                        w.output[at - self.header_len]
                    } else {
                        self.suffix[at - self.header_len - self.body_len]
                    };
                }
            }
        }
        Ok(out.len())
    }
    fn close_classic(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        p.memory.wipe(&mut w.output);
        self.memory(0);
    }
}
impl Default for Piv {
    fn default() -> Self {
        Self::new()
    }
}
pub(super) use super::codec::der_signature;
