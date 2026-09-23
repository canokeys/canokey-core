// SPDX-License-Identifier: Apache-2.0
//! OATH wire schema. Domain/authentication modules have no APDU dependency.
#![forbid(unsafe_code)]

use super::wire::{ins::*, otp_selector, tag};
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
pub const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
pub const CAPACITY: usize = 288;
pub fn status(error: Error) -> Sw {
    match error {
        Error::Missing | Error::AccessCodeMissing => Sw::DATA_INVALID,
        Error::Duplicate | Error::CounterExhausted => Sw::CONDITIONS_NOT_SATISFIED,
        Error::NoSpace => Sw::NOT_ENOUGH_MEMORY,
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
    let name = field(cursor, tag::NAME)?;
    if name.is_empty() || name.len() > 64 {
        return Err(Sw::WRONG_DATA);
    }
    Ok(name)
}
fn challenge<'a>(cursor: &mut ByteCursor<'a>) -> Result<&'a [u8], Sw> {
    let bytes = field(cursor, tag::CHALLENGE)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Sw::WRONG_DATA);
    }
    Ok(bytes)
}
#[derive(Clone, Copy)]
enum Page {
    None,
    List,
    Calculate { truncated: bool },
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
        // SELECT returns version (3 bytes) and persistent applet handle (8 bytes).
        // An access-protected applet also returns an 8-byte authentication
        // challenge and algorithm TLV 7B 01 01 (one-byte value: HMAC-SHA1).
        self.response[..2].copy_from_slice(&[tag::VERSION, 0x03]);
        self.response[2..5].copy_from_slice(&OATH_VERSION);
        self.response[5..7].copy_from_slice(&[tag::NAME, 0x08]);
        self.response[7..15].copy_from_slice(&selected.handle);
        self.length = 15;
        if let Some(challenge) = selected.challenge {
            self.response[15..17].copy_from_slice(&[tag::CHALLENGE, 0x08]);
            self.response[17..25].copy_from_slice(&challenge);
            self.response[25..28].copy_from_slice(&[tag::ALGORITHM, 0x01, 0x01]);
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
        if h.ins != INS_SEND_REMAINING {
            self.page = Page::None;
            self.cursor = 0;
        }
        // Original YubiKey OTP API is deliberately outside the OATH auth gate.
        if h.ins == INS_PUT
            && matches!(
                h.p1,
                otp_selector::SERIAL
                    | otp_selector::CHALLENGE_SLOT_1
                    | otp_selector::CHALLENGE_SLOT_2
            )
        {
            // Legacy OTP uses P1 for the operation/slot; P2 has no options
            // and must be 00 even for HMAC challenge-response requests.
            if h.p2 != 0x00 {
                return Err(Sw::WRONG_P1P2);
            }
            if h.p1 == otp_selector::SERIAL {
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
                let index = u8::from(h.p1 == otp_selector::CHALLENGE_SLOT_2);
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                if !matches!(pass.slot(index), Ok(Slot::Hmac(_))) {
                    return Err(Sw::FILE_NOT_FOUND);
                }
                let mut result = [0; 20];
                pass.challenge(index, data, &mut result, p)
                    .map_err(crate::applets::pass::status)?;
                self.response[..20].copy_from_slice(&result);
                p.memory.wipe(&mut result);
                self.length = 20;
            }
            return Ok(Sw::SUCCESS);
        }
        if !self.session.authorized() && h.ins != INS_VALIDATE {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        // SEND REMAINING has no parameter modes: P1/P2=00 continues the
        // saved credential enumeration, rather than selecting a new page index.
        if h.ins == INS_SEND_REMAINING {
            if h.p1 != 0x00 || h.p2 != 0x00 {
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
            INS_PUT => {
                // Ordinary OATH PUT uses 00/00; kind/algorithm/name are in TLVs.
                // Nonzero legacy OTP P1 selectors were handled before this match.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                let name = name(&mut c)?;
                let key = field(&mut c, tag::KEY)?;
                if key.len() < 3 || key.len() > 66 {
                    return Err(Sw::WRONG_DATA);
                }
                let kind = Kind::from_byte(key[0]).map_err(status)?;
                let alg = Algorithm::from_byte(key[0] & Kind::ALGORITHM_MASK).map_err(status)?;
                let prop = if c.peek() == Some(tag::PROPERTY) {
                    c.byte().map_err(|_| Sw::WRONG_LENGTH)?;
                    c.byte().map_err(|_| Sw::WRONG_LENGTH)?
                } else {
                    0
                };
                let mut moving = [0; 8];
                // The wire HOTP initial counter is four bytes; storage uses
                // an eight-byte big-endian moving factor. TOTP cannot set it.
                if c.peek() == Some(tag::INITIAL_COUNTER) {
                    let counter = field(&mut c, tag::INITIAL_COUNTER)?;
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
            INS_DELETE | INS_RENAME => {
                // P1/P2 are reserved (00); NAME TLVs identify old/new names.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                let old = name(&mut c)?;
                if h.ins == INS_RENAME {
                    let new = name(&mut c)?;
                    service::rename(&mut store, &mut mac, old, new).map_err(status)?;
                } else {
                    let id = service::find(&mut store, &mut mac, old).map_err(status)?;
                    if let Some(pass) = pass {
                        pass.remove_oath(Some(id.0), p.storage, p.memory)
                            .map_err(crate::applets::pass::status)?;
                    }
                    Store::new(p.storage, p.memory).delete(id).map_err(status)?;
                }
            }
            INS_SET_CODE => {
                // P1/P2=00; the KEY field (or empty body) selects set vs clear.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                let key = if data.is_empty() {
                    &[][..]
                } else {
                    field(&mut c, tag::KEY)?
                };
                if key.is_empty() {
                    self.session
                        .clear_code(&mut store, &mut mac)
                        .map_err(status)?;
                } else {
                    if key.len() != 17 {
                        return Err(Sw::WRONG_DATA);
                    }
                    let challenge = field(&mut c, tag::CHALLENGE)?;
                    let response = field(&mut c, tag::RESPONSE)?;
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
                                Sw::DATA_INVALID
                            } else {
                                status(e)
                            }
                        })?;
                }
            }
            INS_VALIDATE => {
                // P1/P2=00; RESPONSE/CHALLENGE TLVs carry the mutual proof.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                let response = field(&mut c, tag::RESPONSE)?
                    .try_into()
                    .map_err(|_| Sw::WRONG_DATA)?;
                let challenge = field(&mut c, tag::CHALLENGE)?;
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
                // RESPONSE contains the full 20-byte HMAC-SHA1 proof.
                self.response[..2].copy_from_slice(&[tag::RESPONSE, 0x14]);
                self.response[2..22].copy_from_slice(&result);
                mac.wipe(&mut result);
                self.length = 22;
            }
            INS_LIST => {
                // P1/P2=00 starts enumeration; continuation uses SEND REMAINING.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                self.page = Page::List;
                return self.page(le, p);
            }
            INS_CALCULATE_ALL => {
                // P1=00; P2=00 returns full MACs, P2=01 dynamic truncation.
                // The challenge is in the body and applies to the whole list.
                if h.p1 != 0x00 || h.p2 > 0x01 {
                    return Err(Sw::WRONG_P1P2);
                }
                let challenge = challenge(&mut c)?;
                self.challenge[..challenge.len()].copy_from_slice(challenge);
                self.challenge_len = challenge.len();
                self.page = Page::Calculate {
                    truncated: h.p2 != 0x00,
                };
                return self.page(le, p);
            }
            INS_CALCULATE => {
                // P1=00; P2=00 returns the full MAC, P2=01 the 31-bit
                // dynamically truncated value. NAME selects the credential.
                if h.p1 != 0x00 || h.p2 > 0x01 {
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
                self.emit_digest(&result, h.p2 != 0x00);
                result.clear(&mut mac);
            }
            INS_SET_DEFAULT => {
                // P1=1/2 selects a PASS slot (one-based); P2=0/1 controls
                // the trailing Enter key. NAME binds an HOTP credential.
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                if !(0x01..=0x02).contains(&h.p1) || h.p2 > 0x01 {
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
                    .map_err(crate::applets::pass::status)
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
            if truncated {
                tag::TRUNCATED_RESPONSE
            } else {
                tag::RESPONSE
            },
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
