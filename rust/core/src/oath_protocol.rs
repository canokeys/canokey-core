// SPDX-License-Identifier: Apache-2.0
//! OATH wire schema only; credential/authentication logic lives in canokey-oath.
#![forbid(unsafe_code)]
use crate::{
    Platform,
    oath_backend::{Mac, Shared, Store},
    pass::Pass,
    services::Record,
};
use canokey_oath::{
    Algorithm, Crypto, Error, auth,
    credential::{Credential, Kind, Properties},
    service::{self, Presence, Repository},
};
use canokey_pass::domain::{Slot, SlotIndex};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw, tlv::ByteCursor};
use core::cell::RefCell;
pub const AID: &[u8] = &[0xa0, 0, 0, 5, 0x27, 0x21, 1];
pub const CAPACITY: usize = 288;
const DATA_INVALID: Sw = Sw(0x6984);
pub fn status(error: Error) -> Sw {
    match error {
        Error::Missing => DATA_INVALID,
        Error::Duplicate | Error::CounterExhausted => Sw::CONDITIONS_NOT_SATISFIED,
        Error::NoSpace => Sw(0x6a84),
        Error::Unauthorized | Error::PresenceRequired | Error::IncreasingChallenge => {
            Sw::SECURITY_STATUS_NOT_SATISFIED
        }
        Error::Invalid => Sw::WRONG_DATA,
        _ => Sw::UNABLE_TO_PROCESS,
    }
}
fn field<'a>(cursor: &mut ByteCursor<'a>, expected: u8) -> Result<&'a [u8], Sw> {
    let (tag, value) = cursor.field().map_err(|_| Sw::WRONG_LENGTH)?;
    if tag != expected {
        return Err(Sw::WRONG_DATA);
    }
    Ok(value)
}
fn name<'a>(cursor: &mut ByteCursor<'a>) -> Result<&'a [u8], Sw> {
    let name = field(cursor, 0x71)?;
    if name.is_empty() || name.len() > 64 {
        return Err(Sw::WRONG_DATA);
    }
    Ok(name)
}
fn challenge<'a>(cursor: &mut ByteCursor<'a>) -> Result<&'a [u8], Sw> {
    let bytes = field(cursor, 0x74)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Sw::WRONG_DATA);
    }
    Ok(bytes)
}
#[derive(Clone, Copy)]
enum Page {
    None,
    List,
    Calculate(bool),
}
pub struct Oath {
    session: auth::Session,
    command: [u8; CAPACITY],
    used: usize,
    response: [u8; 256],
    length: usize,
    page: Page,
    cursor: u32,
    challenge: [u8; 8],
    challenge_len: usize,
    pub consumed_presence: bool,
}
impl Oath {
    pub const fn new() -> Self {
        Self {
            session: auth::Session::new(),
            command: [0; CAPACITY],
            used: 0,
            response: [0; 256],
            length: 0,
            page: Page::None,
            cursor: 0,
            challenge: [0; 8],
            challenge_len: 0,
            consumed_presence: false,
        }
    }
    pub fn install(&mut self, p: &mut dyn Platform) -> Result<(), Sw> {
        let shared = RefCell::new(p);
        let mut store = Store(&shared);
        let mut mac = Mac(&shared);
        match store.install() {
            Err(Error::Missing) => shared
                .borrow_mut()
                .replace(Record::OathRecords, &[])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?,
            Ok(()) => (),
            Err(e) => return Err(status(e)),
        }
        auth::install(&mut store, &mut mac).map_err(status)
    }
    pub fn reset(&mut self, p: &mut dyn Platform) {
        self.cancel_command(p);
        p.wipe(&mut self.response);
        self.length = 0;
        self.page = Page::None;
        self.cursor = 0;
        p.wipe(&mut self.challenge);
        self.challenge_len = 0;
        self.session.reset(&mut Mac(&RefCell::new(p)));
    }
    pub fn select(&mut self, p: &mut dyn Platform) -> Result<u32, Sw> {
        self.reset(p);
        let shared = RefCell::new(p);
        let selected = self
            .session
            .select(&mut Store(&shared), &mut Mac(&shared))
            .map_err(status)?;
        self.response[..7].copy_from_slice(&[0x79, 3, 6, 0, 0, 0x71, 8]);
        self.response[7..15].copy_from_slice(&selected.handle);
        self.length = 15;
        if let Some(challenge) = selected.challenge {
            self.response[15..17].copy_from_slice(&[0x74, 8]);
            self.response[17..25].copy_from_slice(&challenge);
            self.response[25..28].copy_from_slice(&[0x7b, 1, 1]);
            self.length = 28;
        }
        Ok(self.length as u32)
    }
    pub fn cancel_command(&mut self, p: &mut dyn Platform) {
        p.wipe(&mut self.command);
        self.used = 0;
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|n| *n <= CAPACITY)
            .ok_or(Sw::WRONG_LENGTH)?;
        self.command[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        let end = offset.checked_add(out.len()).ok_or(Sw::WRONG_LENGTH)?;
        out.copy_from_slice(
            self.response[..self.length]
                .get(offset..end)
                .ok_or(Sw::WRONG_LENGTH)?,
        );
        Ok(())
    }
    pub fn finish(
        &mut self,
        h: Header,
        le: u32,
        pass: &mut Pass,
        p: &mut dyn Platform,
    ) -> Result<(u32, Sw), Sw> {
        // Owned bounded request fields, never a borrowed transport/PKE tail.
        let mut command = core::mem::replace(&mut self.command, [0; CAPACITY]);
        let n = self.used;
        self.used = 0;
        self.length = 0;
        let result = self.execute(h, le, &command[..n], pass, p);
        p.wipe(&mut command);
        result.map(|sw| (self.length as u32, sw))
    }
    pub fn clear(&mut self, pass: &mut Pass, p: &mut dyn Platform) -> Result<(), Sw> {
        self.reset(p);
        pass.remove_oath(None, p)
            .map_err(crate::admin::pass_error)?;
        p.replace(Record::OathRecords, &[])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        let shared = RefCell::new(p);
        let mut mac = Mac(&shared);
        let metadata = auth::Metadata::new(&mut mac).map_err(status)?;
        auth::Repository::replace(&mut Store(&shared), &metadata).map_err(status)
    }
    fn execute(
        &mut self,
        h: Header,
        le: u32,
        data: &[u8],
        pass: &mut Pass,
        p: &mut dyn Platform,
    ) -> Result<Sw, Sw> {
        if h.ins != 0xa5 {
            self.page = Page::None;
            self.cursor = 0;
        }
        // Original YubiKey OTP API is deliberately outside the OATH auth gate.
        if h.ins == 1 && matches!(h.p1, 0x10 | 0x30 | 0x38) {
            if h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if h.p1 == 0x10 {
                if !data.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                let mut serial = [0; 4];
                p.serial(&mut serial);
                self.response[..4].copy_from_slice(&serial);
                self.length = 4;
            } else {
                if data.len() > 64 {
                    return Err(Sw::WRONG_LENGTH);
                }
                let index = u8::from(h.p1 == 0x38);
                if !matches!(pass.slot(index), Ok(Slot::Hmac(_))) {
                    return Err(Sw::FILE_NOT_FOUND);
                }
                let mut result = [0; 20];
                pass.challenge(index, data, &mut result, p)
                    .map_err(crate::admin::pass_error)?;
                self.response[..20].copy_from_slice(&result);
                p.wipe(&mut result);
                self.length = 20;
            }
            return Ok(Sw::SUCCESS);
        }
        if !self.session.authorized() && h.ins != 0xa3 {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if h.ins == 0xa5 {
            match self.page {
                Page::List if h.p1 != 0 || h.p2 != 0 => return Err(Sw::WRONG_P1P2),
                Page::Calculate(_) if h.p2 > 1 => return Err(Sw::WRONG_P1P2),
                _ => (),
            }
            return self.page(le, p);
        }
        let shared = RefCell::new(p);
        let mut store = Store(&shared);
        let mut mac = Mac(&shared);
        let mut c = ByteCursor::new(data);
        match h.ins {
            1 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                let name = name(&mut c)?;
                let key = field(&mut c, 0x73)?;
                if key.len() < 3 || key.len() > 66 {
                    return Err(Sw::WRONG_DATA);
                }
                let kind = match key[0] & 0xf0 {
                    0x10 => Kind::Hotp,
                    0x20 => Kind::Totp,
                    _ => return Err(Sw::WRONG_DATA),
                };
                let alg = Algorithm::from_byte(key[0] & 15).map_err(status)?;
                let prop = if c.peek() == Some(0x78) {
                    c.byte().map_err(|_| Sw::WRONG_LENGTH)?;
                    c.byte().map_err(|_| Sw::WRONG_LENGTH)?
                } else {
                    0
                };
                let mut moving = [0; 8];
                if c.peek() == Some(0x7a) {
                    let counter = field(&mut c, 0x7a)?;
                    if counter.len() != 4 || kind != Kind::Hotp {
                        return Err(Sw::WRONG_DATA);
                    }
                    moving[4..].copy_from_slice(counter);
                }
                if !c.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                let mut record = Credential::new(
                    name,
                    &key[2..],
                    kind,
                    alg,
                    key[1],
                    Properties::new(prop).map_err(status)?,
                    moving,
                )
                .map_err(status)?;
                let result = service::put(&mut store, &mut mac, &record).map_err(status);
                record.clear(&mut mac);
                result?;
            }
            2 | 5 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                let old = name(&mut c)?;
                if h.ins == 5 {
                    let new = name(&mut c)?;
                    service::rename(&mut store, &mut mac, old, new).map_err(status)?;
                } else {
                    let id = service::find(&mut store, &mut mac, old).map_err(status)?;
                    pass.remove_oath(Some(id.0), &mut **shared.borrow_mut())
                        .map_err(crate::admin::pass_error)?;
                    store.delete(id).map_err(status)?;
                }
            }
            3 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                let key = if data.is_empty() {
                    &[][..]
                } else {
                    field(&mut c, 0x73)?
                };
                if key.is_empty() {
                    self.session
                        .clear_code(&mut store, &mut mac)
                        .map_err(status)?;
                } else {
                    if key.len() != 17 {
                        return Err(Sw::WRONG_DATA);
                    }
                    let challenge = field(&mut c, 0x74)?;
                    let response = field(&mut c, 0x75)?;
                    if !c.is_empty() {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    let response = response.try_into().map_err(|_| Sw::WRONG_DATA)?;
                    self.session
                        .set_code(
                            &mut store,
                            &mut mac,
                            key[1..].try_into().unwrap(),
                            challenge,
                            response,
                        )
                        .map_err(|e| {
                            if e == Error::Invalid {
                                DATA_INVALID
                            } else {
                                status(e)
                            }
                        })?;
                }
            }
            0xa3 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                let response = field(&mut c, 0x75)?
                    .try_into()
                    .map_err(|_| Sw::WRONG_DATA)?;
                let challenge = field(&mut c, 0x74)?;
                if !c.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                let mut result = [0; 20];
                self.session
                    .validate(&mut store, &mut mac, response, challenge, &mut result)
                    .map_err(|e| {
                        if e == Error::Unauthorized {
                            Sw::WRONG_DATA
                        } else {
                            status(e)
                        }
                    })?;
                self.response[..2].copy_from_slice(&[0x75, 20]);
                self.response[2..22].copy_from_slice(&result);
                mac.wipe(&mut result);
                self.length = 22;
            }
            0xa1 => {
                if h.p1 != 0 || h.p2 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                self.page = Page::List;
                return self.page_shared(le, &shared);
            }
            0xa4 => {
                if h.p1 != 0 || h.p2 > 1 {
                    return Err(Sw::WRONG_P1P2);
                }
                let challenge = challenge(&mut c)?;
                self.challenge[..challenge.len()].copy_from_slice(challenge);
                self.challenge_len = challenge.len();
                self.page = Page::Calculate(h.p2 != 0);
                return self.page_shared(le, &shared);
            }
            0xa2 => {
                if h.p1 != 0 || h.p2 > 1 {
                    return Err(Sw::WRONG_P1P2);
                }
                let name = name(&mut c)?;
                let id = service::find(&mut store, &mut mac, name).map_err(status)?;
                let mut record = store.load(id).map_err(status)?;
                let kind = record.kind();
                let touch = record.properties().touch();
                record.clear(&mut mac);
                let input = if kind == Kind::Totp {
                    challenge(&mut c)?
                } else {
                    &[]
                };
                let presence = if touch {
                    self.consumed_presence = true;
                    if !crate::presence::wait(&mut **shared.borrow_mut()) {
                        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                    }
                    Presence::Confirmed
                } else {
                    Presence::NotConfirmed
                };
                let mut result = service::calculate(&mut store, &mut mac, id, input, presence)
                    .map_err(status)?;
                self.emit_digest(&result, h.p2 != 0);
                result.clear(&mut mac);
            }
            0x55 => {
                if !(1..=2).contains(&h.p1) || h.p2 > 1 {
                    return Err(Sw::WRONG_P1P2);
                }
                let name = name(&mut c)?;
                let id = service::find(&mut store, &mut mac, name).map_err(status)?;
                let mut record = store.load(id).map_err(status)?;
                let result = if record.kind() != Kind::Hotp {
                    Err(Sw::CONDITIONS_NOT_SATISFIED)
                } else {
                    pass.configure(
                        SlotIndex::new(h.p1 - 1).unwrap(),
                        Slot::Oath {
                            id: id.0,
                            name: record.name(),
                            enter: h.p2,
                        },
                        &mut **shared.borrow_mut(),
                    )
                    .map_err(crate::admin::pass_error)
                };
                record.clear(&mut mac);
                result?;
            }
            _ => return Err(Sw::INS_NOT_SUPPORTED),
        }
        Ok(Sw::SUCCESS)
    }
    fn emit_digest(&mut self, digest: &service::Digest, truncated: bool) {
        let at = self.length;
        let n = if truncated { 4 } else { digest.bytes().len() };
        self.response[at..at + 3].copy_from_slice(&[
            if truncated { 0x76 } else { 0x75 },
            (n + 1) as u8,
            digest.digits(),
        ]);
        if truncated {
            self.response[at + 3..at + 7].copy_from_slice(&digest.truncated().to_be_bytes());
        } else {
            self.response[at + 3..at + 3 + n].copy_from_slice(digest.bytes());
        }
        self.length += 3 + n;
    }
    fn page(&mut self, le: u32, p: &mut dyn Platform) -> Result<Sw, Sw> {
        self.page_shared(le, &RefCell::new(p))
    }
    fn page_shared(&mut self, le: u32, shared: &Shared<'_>) -> Result<Sw, Sw> {
        let mut store = Store(shared);
        let mut mac = Mac(shared);
        let total = store.count().map_err(status)?;
        let capacity = le.min(256) as usize;
        if matches!(self.page, Page::None) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        while self.cursor < total {
            let Some(id) = store.at(self.cursor).map_err(status)? else {
                self.cursor += 1;
                continue;
            };
            let mut record = store.load(id).map_err(status)?;
            let estimate = match self.page {
                Page::List => 3 + record.name().len(),
                Page::Calculate(t) => 5 + record.name().len() + if t { 4 } else { 64 },
                Page::None => 0,
            };
            if self.length + estimate > capacity {
                record.clear(&mut mac);
                return Ok(Sw(0x61ff));
            }
            self.cursor += 1;
            let at = self.length;
            match self.page {
                Page::List => {
                    self.response[at..at + 3].copy_from_slice(&[
                        0x72,
                        (record.name().len() + 1) as u8,
                        record.kind() as u8 | record.algorithm() as u8,
                    ]);
                    self.response[at + 3..at + 3 + record.name().len()]
                        .copy_from_slice(record.name());
                    self.length += 3 + record.name().len();
                }
                Page::Calculate(truncated) => {
                    self.response[at..at + 2].copy_from_slice(&[0x71, record.name().len() as u8]);
                    self.response[at + 2..at + 2 + record.name().len()]
                        .copy_from_slice(record.name());
                    self.length += 2 + record.name().len();
                    let marker = if record.kind() == Kind::Hotp {
                        Some(0x77)
                    } else if record.properties().touch() {
                        Some(0x7c)
                    } else {
                        None
                    };
                    if let Some(tag) = marker {
                        let at = self.length;
                        self.response[at..at + 3].copy_from_slice(&[tag, 1, record.digits()]);
                        self.length += 3;
                    } else {
                        // Preserve C CALCULATE ALL's historical handling of a
                        // decreasing challenge: calculate without lowering the stored value.
                        let input = &self.challenge[..self.challenge_len];
                        let result = if record.properties().increasing()
                            && (input.len() != 8 || input < &record.moving_factor()[..])
                        {
                            service::calculate_untracked(&record, &mut mac, input)
                        } else {
                            service::calculate(
                                &mut store,
                                &mut mac,
                                id,
                                input,
                                Presence::NotConfirmed,
                            )
                        };
                        record.clear(&mut mac);
                        let mut result = result.map_err(status)?;
                        self.emit_digest(&result, truncated);
                        result.clear(&mut mac);
                    }
                }
                Page::None => (),
            }
            record.clear(&mut mac);
        }
        self.page = Page::None;
        Ok(Sw::SUCCESS)
    }
}
