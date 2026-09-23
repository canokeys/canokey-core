// SPDX-License-Identifier: Apache-2.0
//! OATH wire schema. Domain/authentication modules have no APDU dependency.
#![forbid(unsafe_code)]
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth,
    credential::{Credential, Kind, Properties},
    service::{self, Presence, Repository},
};
use crate::applets::pass::domain::{Slot, SlotIndex};
use crate::{
    Platform,
    applets::oath::repository::{Mac, Store},
    applets::pass::service::Pass,
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw, tlv::ByteCursor};
mod paging;
include!(concat!(env!("OUT_DIR"), "/oath_version.rs"));
pub const AID: &[u8] = &[0xa0, 0, 0, 5, 0x27, 0x21, 1];
pub const CAPACITY: usize = 288;
const DATA_INVALID: Sw = Sw(0x6984);
pub fn status(error: Error) -> Sw {
    match error {
        Error::Missing | Error::AccessCodeMissing => DATA_INVALID,
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
struct State {
    session: auth::Session,
    response: [u8; 256],
    length: usize,
    page: Page,
    cursor: u32,
    challenge: [u8; 8],
    challenge_len: usize,
    // Even a failed wait consumes its input epoch; never replay it into PASS.
    presence: crate::runtime::presence::Request,
}
impl State {
    pub const fn new() -> Self {
        Self {
            session: auth::Session::new(),
            response: [0; 256],
            length: 0,
            page: Page::None,
            cursor: 0,
            challenge: [0; 8],
            challenge_len: 0,
            presence: crate::runtime::presence::Request::new(),
        }
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
        match store.install() {
            Err(Error::Missing) => store.initialize().map_err(status)?,
            Ok(()) => (),
            Err(e) => return Err(status(e)),
        }
        auth::install(&mut store, &mut mac).map_err(status)
    }
    pub fn reset(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.response);
        self.length = 0;
        self.page = Page::None;
        self.cursor = 0;
        p.memory.wipe(&mut self.challenge);
        self.challenge_len = 0;
        self.session.reset(&mut Mac::new(p.crypto, p.memory));
    }
    pub fn select(&mut self, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.reset(p);
        let selected = self
            .session
            .select(
                &mut Store::new(p.storage, p.memory),
                &mut Mac::new(p.crypto, p.memory),
            )
            .map_err(status)?;
        self.response[..2].copy_from_slice(&[0x79, 3]);
        self.response[2..5].copy_from_slice(&OATH_VERSION);
        self.response[5..7].copy_from_slice(&[0x71, 8]);
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
    pub fn close_response(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.response);
        self.length = 0;
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
    fn execute(
        &mut self,
        h: Header,
        le: u32,
        data: &[u8],
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
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
                p.device.serial(&mut serial);
                self.response[..4].copy_from_slice(&serial);
                self.length = 4;
            } else {
                if data.len() > 64 {
                    return Err(Sw::WRONG_LENGTH);
                }
                let index = u8::from(h.p1 == 0x38);
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                if !matches!(pass.slot(index), Ok(Slot::Hmac(_))) {
                    return Err(Sw::FILE_NOT_FOUND);
                }
                let mut result = [0; 20];
                pass.challenge(index, data, &mut result, p)
                    .map_err(pass_error)?;
                self.response[..20].copy_from_slice(&result);
                p.memory.wipe(&mut result);
                self.length = 20;
            }
            return Ok(Sw::SUCCESS);
        }
        if !self.session.authorized() && h.ins != 0xa3 {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if h.ins == 0xa5 {
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if !data.is_empty() {
                return Err(Sw::WRONG_LENGTH);
            }
            return self.page(le, p);
        }
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
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
                    if let Some(pass) = pass {
                        pass.remove_oath(Some(id.0), p.storage, p.memory)
                            .map_err(pass_error)?;
                    }
                    Store::new(p.storage, p.memory).delete(id).map_err(status)?;
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
                return self.page(le, p);
            }
            0xa4 => {
                if h.p1 != 0 || h.p2 > 1 {
                    return Err(Sw::WRONG_P1P2);
                }
                let challenge = challenge(&mut c)?;
                self.challenge[..challenge.len()].copy_from_slice(challenge);
                self.challenge_len = challenge.len();
                self.page = Page::Calculate(h.p2 != 0);
                return self.page(le, p);
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
                    if !self.presence.wait(p.device) {
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
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
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
                        p.storage,
                        p.memory,
                    )
                    .map_err(pass_error)
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
}

/// Request collection and response/session state have disjoint borrows. Execute
/// reads the small bounded request directly; it never copies a second 288-byte
/// command onto the stack to work around a self borrow.
pub struct Oath {
    command: [u8; CAPACITY],
    used: usize,
    state: State,
}
impl Oath {
    pub const fn new() -> Self {
        Self {
            command: [0; CAPACITY],
            used: 0,
            state: State::new(),
        }
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.state.install(p)
    }
    pub fn reset(&mut self, p: &mut Platform<'_>) {
        self.cancel_command(p);
        self.state.reset(p);
    }
    pub fn select(&mut self, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.cancel_command(p);
        self.state.select(p)
    }
    #[cfg(feature = "pass")]
    pub fn take_presence(&mut self) -> bool {
        self.state.presence.take()
    }
    pub fn cancel_command(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.command);
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
        self.state.read_response(offset, out)
    }
    pub fn close_response(&mut self, p: &mut Platform<'_>) {
        self.state.close_response(p);
    }
    // Keep OATH temporaries out of unrelated asymmetric-crypto call paths.
    #[cfg_attr(feature = "openpgp", inline(never))]
    pub fn finish(
        &mut self,
        h: Header,
        le: u32,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        self.state.length = 0;
        let result = self
            .state
            .execute(h, le, &self.command[..self.used], pass, p);
        self.cancel_command(p);
        if result.is_err() {
            self.state.page = Page::None;
            self.state.cursor = 0;
            self.state.close_response(p);
        }
        result.map(|sw| (self.state.length as u32, sw))
    }
}

fn pass_error(error: crate::applets::pass::domain::Error) -> Sw {
    match error {
        crate::applets::pass::domain::Error::Persistence => Sw::UNABLE_TO_PROCESS,
        _ => Sw::WRONG_DATA,
    }
}
