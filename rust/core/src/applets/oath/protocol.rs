// SPDX-License-Identifier: Apache-2.0
//! OATH wire schema. Domain/authentication modules have no APDU dependency.
#![forbid(unsafe_code)]

use super::wire::{ins::*, otp_selector, tag};
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth, credential,
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
const NAME_LIMIT: usize = credential::NAME_LIMIT;
const CHALLENGE_LIMIT: usize = auth::CHALLENGE_BYTES;
const KEY_HEADER_BYTES: usize = 2;
const OATH_KEY_LIMIT: usize = credential::KEY_LIMIT;
const SET_CODE_KEY_BYTES: usize = 1 + 16;
const SET_CODE_ALGORITHM: u8 = 0x01;
const OTP_INPUT_LIMIT: usize = 64;
// Share the status lookup instead of cloning it into each protocol/flow caller.
#[inline(never)]
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
fn proof_status(error: Error) -> Sw {
    // Both malformed proofs and a wrong secret deliberately expose the same
    // 6A80 wire result; callers must not distinguish which proof failed.
    match error {
        Error::Invalid | Error::Unauthorized => Sw::WRONG_DATA,
        other => status(other),
    }
}
fn field<'a>(cursor: &mut ByteCursor<'a>, expected: u8) -> Result<&'a [u8], Sw> {
    let (tag, value) = cursor.field().map_err(|_| Sw::WRONG_LENGTH)?;
    if tag != expected {
        return Err(Sw::WRONG_DATA);
    }
    Ok(value)
}
fn bounded_field<'a>(
    cursor: &mut ByteCursor<'a>,
    expected: u8,
    min: usize,
    max: usize,
) -> Result<&'a [u8], Sw> {
    let tag = cursor.byte().map_err(|_| Sw::WRONG_LENGTH)?;
    let len = usize::from(cursor.byte().map_err(|_| Sw::WRONG_LENGTH)?);
    // Preserve legacy semantic-length precedence without ever reading past
    // the received bytes: an impossible declaration is 6A80, truncation 6700.
    if tag != expected || len < min || len > max {
        return Err(Sw::WRONG_DATA);
    }
    cursor.take(len).map_err(|_| Sw::WRONG_LENGTH)
}
fn name<'a>(cursor: &mut ByteCursor<'a>) -> Result<&'a [u8], Sw> {
    // Validate at the wire boundary before borrowing storage; Credential::new
    // repeats the invariant for callers that construct domain values directly.
    let name = field(cursor, tag::NAME)?;
    if name.is_empty() || name.len() > NAME_LIMIT {
        return Err(Sw::WRONG_DATA);
    }
    Ok(name)
}
fn challenge<'a>(cursor: &mut ByteCursor<'a>) -> Result<&'a [u8], Sw> {
    // Keep challenge validation at the protocol boundary; callers may then
    // safely apply the session's challenge semantics without rechecking size.
    bounded_field(cursor, tag::CHALLENGE, 1, CHALLENGE_LIMIT)
}
// Run after the legacy OTP route and OATH access-code gate. These checks
// precede TLV parsing, storage reads, and presence requests for every command.
fn validate_parameters(h: Header) -> Result<(), Sw> {
    let valid = match h.ins {
        INS_PUT | INS_DELETE | INS_RENAME | INS_SET_CODE | INS_VALIDATE | INS_LIST
        | INS_SEND_REMAINING => h.p1 == 0 && h.p2 == 0,
        INS_CALCULATE | INS_CALCULATE_ALL => h.p1 == 0 && h.p2 <= 1,
        // Missing PASS must remain INS_NOT_SUPPORTED even with invalid P1/P2.
        INS_SET_DEFAULT => true,
        _ => return Err(Sw::INS_NOT_SUPPORTED),
    };
    if valid { Ok(()) } else { Err(Sw::WRONG_P1P2) }
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
    challenge: [u8; CHALLENGE_LIMIT],
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
            challenge: [0; CHALLENGE_LIMIT],
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
        self.encode_select(selected);
        Ok(self.length as u32)
    }
    fn encode_select(&mut self, selected: auth::Selection) {
        const VERSION_VALUE_BYTES: usize = 3;
        const HANDLE_VALUE_BYTES: usize = auth::HANDLE_BYTES;
        self.response[..2].copy_from_slice(&[tag::VERSION, VERSION_VALUE_BYTES as u8]);
        self.response[2..2 + VERSION_VALUE_BYTES].copy_from_slice(&OATH_VERSION);
        let name_at = 2 + VERSION_VALUE_BYTES;
        self.response[name_at..name_at + 2].copy_from_slice(&[tag::NAME, HANDLE_VALUE_BYTES as u8]);
        let handle_at = name_at + 2;
        self.response[handle_at..handle_at + HANDLE_VALUE_BYTES].copy_from_slice(&selected.handle);
        self.length = handle_at + HANDLE_VALUE_BYTES;
        if let Some(challenge) = selected.challenge {
            let challenge_at = self.length;
            self.response[challenge_at..challenge_at + 2]
                .copy_from_slice(&[tag::CHALLENGE, auth::CHALLENGE_BYTES as u8]);
            let value_at = challenge_at + 2;
            self.response[value_at..value_at + auth::CHALLENGE_BYTES].copy_from_slice(&challenge);
            let algorithm_at = value_at + auth::CHALLENGE_BYTES;
            self.response[algorithm_at..algorithm_at + 3].copy_from_slice(&[
                tag::ALGORITHM,
                0x01,
                0x01,
            ]);
            self.length = algorithm_at + 3;
        }
    }
    pub fn close_response(&mut self, p: &mut Platform<'_>) {
        crate::applets::close_response(p.memory, &mut self.response, &mut self.length);
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        crate::applets::read_response_chunk(&self.response, self.length, offset, out)
    }
    fn execute_put(
        &mut self,
        mut c: &mut ByteCursor<'_>,
        store: &mut Store<'_>,
        mac: &mut Mac<'_>,
    ) -> Result<(), Sw> {
        let name = name(&mut c)?;
        let key = bounded_field(
            &mut c,
            tag::KEY,
            KEY_HEADER_BYTES + 1,
            KEY_HEADER_BYTES + OATH_KEY_LIMIT,
        )?;
        // KEY starts with the OATH kind/algorithm byte; the remaining
        // bytes are the secret material.
        let kind = Kind::from_byte(key[0]).map_err(status)?;
        let alg = Algorithm::from_byte(key[0] & Kind::ALGORITHM_MASK).map_err(status)?;
        let prop = if c.peek() == Some(tag::PROPERTY) {
            c.byte().map_err(|_| Sw::WRONG_LENGTH)?;
            c.byte().map_err(|_| Sw::WRONG_LENGTH)?
        } else {
            0
        };
        let mut moving = [0; super::codec::COUNTER_BYTES];
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
            &key[KEY_HEADER_BYTES..],
            kind,
            alg,
            key[1],
            Properties::new(prop).map_err(status)?,
            moving,
        )
        .map_err(status)?;
        let result = service::put(store, mac, &record).map_err(status);
        record.clear(mac);
        result?;
        Ok(())
    }

    fn execute_delete_rename(
        &mut self,
        h: Header,
        mut c: &mut ByteCursor<'_>,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
        let old = name(&mut c)?;
        if h.ins == INS_RENAME {
            let new = name(&mut c)?;
            if !c.is_empty() {
                return Err(Sw::WRONG_LENGTH);
            }
            service::rename(&mut store, &mut mac, old, new).map_err(status)?;
        } else {
            if !c.is_empty() {
                return Err(Sw::WRONG_LENGTH);
            }
            let id = service::find(&mut store, &mut mac, old).map_err(status)?;
            drop(store);
            if let Some(pass) = pass {
                pass.remove_oath(Some(id.0), p.storage, p.memory)
                    .map_err(crate::applets::pass::status)?;
            }
            // PASS and OATH share the storage borrow; recreate the store only
            // after PASS has released it so both records remain consistent.
            Store::new(p.storage, p.memory).delete(id).map_err(status)?;
        }
        Ok(())
    }

    fn execute_set_code(
        &mut self,
        data: &[u8],
        mut c: &mut ByteCursor<'_>,
        store: &mut Store<'_>,
        mac: &mut Mac<'_>,
    ) -> Result<(), Sw> {
        let key = if data.is_empty() {
            &[][..]
        } else {
            field(&mut c, tag::KEY)?
        };
        if key.is_empty() {
            self.session.clear_code(store, mac).map_err(status)?;
        } else {
            if key.len() != SET_CODE_KEY_BYTES {
                return Err(Sw::WRONG_DATA);
            }
            if key[0] != SET_CODE_ALGORITHM {
                return Err(Sw::WRONG_DATA);
            }
            let challenge = challenge(&mut c)?;
            let response = field(&mut c, tag::RESPONSE)?;
            if !c.is_empty() {
                return Err(Sw::WRONG_LENGTH);
            }
            let response = response.try_into().map_err(|_| Sw::WRONG_DATA)?;
            self.session
                .set_code(
                    store,
                    mac,
                    key[1..].try_into().unwrap(),
                    challenge,
                    response,
                )
                .map_err(proof_status)?;
        }
        Ok(())
    }

    fn execute_validate(
        &mut self,
        mut c: &mut ByteCursor<'_>,
        store: &mut Store<'_>,
        mac: &mut Mac<'_>,
    ) -> Result<(), Sw> {
        let response = field(&mut c, tag::RESPONSE)?
            .try_into()
            .map_err(|_| Sw::WRONG_DATA)?;
        let challenge = field(&mut c, tag::CHALLENGE)?;
        if !c.is_empty() {
            return Err(Sw::WRONG_LENGTH);
        }
        let mut result = [0; 20];
        self.session
            .validate(store, mac, response, challenge, &mut result)
            .map_err(proof_status)?;
        // RESPONSE contains the full 20-byte HMAC-SHA1 proof.
        self.response[..2].copy_from_slice(&[tag::RESPONSE, 0x14]);
        self.response[2..22].copy_from_slice(&result);
        mac.wipe(&mut result);
        self.length = 22;
        Ok(())
    }

    fn execute_calculate(
        &mut self,
        h: Header,
        mut c: &mut ByteCursor<'_>,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
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
        if !c.is_empty() {
            return Err(Sw::WRONG_LENGTH);
        }
        let presence = if touch {
            if !self.presence.wait(p.device) {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            Presence::Confirmed
        } else {
            Presence::NotConfirmed
        };
        let mut result =
            service::calculate(&mut store, &mut mac, id, input, presence).map_err(status)?;
        self.emit_digest(&result, h.p2 != 0x00);
        result.clear(&mut mac);
        Ok(())
    }

    fn execute_set_default(
        &mut self,
        h: Header,
        mut c: &mut ByteCursor<'_>,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
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
                if data.len() > OTP_INPUT_LIMIT {
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
        validate_parameters(h)?;
        // SEND REMAINING has no parameter modes: P1/P2=00 continues the
        // saved credential enumeration, rather than selecting a new page index.
        if h.ins == INS_SEND_REMAINING {
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
                self.execute_put(&mut c, &mut store, &mut mac)?;
            }
            INS_DELETE | INS_RENAME => {
                // Store borrows the shared storage/memory handles; release it
                // before the delete helper creates its transactional Store.
                drop(store);
                drop(mac);
                self.execute_delete_rename(h, &mut c, pass, p)?;
            }
            INS_SET_CODE => {
                self.execute_set_code(data, &mut c, &mut store, &mut mac)?;
            }
            INS_VALIDATE => {
                self.execute_validate(&mut c, &mut store, &mut mac)?;
            }
            INS_LIST => {
                // P1/P2=00 starts enumeration; continuation uses SEND REMAINING.
                self.page = Page::List;
                return self.page(le, p);
            }
            INS_CALCULATE_ALL => {
                // P1=00; P2=00 returns full MACs, P2=01 dynamic truncation.
                // The challenge is in the body and applies to the whole list.
                let challenge = challenge(&mut c)?;
                if !c.is_empty() {
                    return Err(Sw::WRONG_LENGTH);
                }
                self.challenge[..challenge.len()].copy_from_slice(challenge);
                self.challenge_len = challenge.len();
                self.page = Page::Calculate {
                    truncated: h.p2 != 0x00,
                };
                return self.page(le, p);
            }
            INS_CALCULATE => {
                drop(store);
                drop(mac);
                self.execute_calculate(h, &mut c, p)?;
            }
            INS_SET_DEFAULT => {
                drop(store);
                drop(mac);
                self.execute_set_default(h, &mut c, pass, p)?;
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

#[cfg(test)]
mod parameter_tests {
    use super::*;
    use crate::ports::{CryptoError, Device, Memory, Record, Storage, StorageError};

    struct MetadataOnly {
        locked: bool,
        selecting: bool,
    }
    impl Storage for MetadataOnly {
        fn load(&mut self, record: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            assert!(
                self.selecting,
                "parameter rejection must precede storage reads"
            );
            assert_eq!(record, Record::OathMetadata);
            out.fill(0);
            out[0] = 1;
            out[1] = u8::from(self.locked);
            Ok(if self.locked { 26 } else { 10 })
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            panic!("parameter rejection must not write storage")
        }
    }
    struct NoMac;
    impl crate::ports::Crypto for NoMac {
        fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
            panic!("parameter rejection must precede MAC operations")
        }
        fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
            out.fill(0x5a);
            Ok(())
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            panic!("parameter rejection must precede MAC operations")
        }
    }
    struct NoPresence;
    impl Device for NoPresence {
        fn serial(&mut self, out: &mut [u8; 4]) {
            *out = [1, 2, 3, 4];
        }
        fn now(&mut self) -> u32 {
            0
        }
        fn touched(&mut self) -> bool {
            panic!("parameter rejection must precede touch")
        }
        fn progress(&mut self) -> bool {
            panic!("parameter rejection must not yield")
        }
        fn led(&mut self, _: bool) {}
    }
    struct Wipe;
    impl Memory for Wipe {
        fn wipe(&self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
    }

    #[test]
    fn parameter_rejection_preserves_auth_legacy_and_parse_precedence() {
        for locked in [false, true] {
            let mut storage = MetadataOnly {
                locked,
                selecting: true,
            };
            let mut crypto = NoMac;
            let mut device = NoPresence;
            let mut state = State::new();
            state
                .select(&mut Platform {
                    storage: &mut storage,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &Wipe,
                })
                .unwrap();
            storage.selecting = false;
            let mut p = Platform {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &Wipe,
            };
            for ins in [
                INS_PUT,
                INS_DELETE,
                INS_RENAME,
                INS_SET_CODE,
                INS_LIST,
                INS_VALIDATE,
                INS_SEND_REMAINING,
                INS_CALCULATE,
                INS_CALCULATE_ALL,
            ] {
                for (p1, p2) in [(1, 0), (0, 2), (0xff, 0xff)] {
                    let h = Header {
                        cla: 0,
                        ins,
                        p1,
                        p2,
                    };
                    // A truncated NAME TLV must not obscure parameter/auth errors.
                    assert_eq!(
                        state.execute(h, 256, &[tag::NAME, 0xff], None, &mut p),
                        Err(if locked && ins != INS_VALIDATE {
                            Sw::SECURITY_STATUS_NOT_SATISFIED
                        } else {
                            Sw::WRONG_P1P2
                        })
                    );
                }
            }
            for ins in [INS_SET_DEFAULT, 0xff] {
                assert_eq!(
                    state.execute(
                        Header {
                            cla: 0,
                            ins,
                            p1: 0xff,
                            p2: 0xff
                        },
                        256,
                        &[],
                        None,
                        &mut p
                    ),
                    Err(if locked {
                        Sw::SECURITY_STATUS_NOT_SATISFIED
                    } else {
                        Sw::INS_NOT_SUPPORTED
                    })
                );
            }
            // The legacy serial route remains available outside the access-code gate.
            let h = Header {
                cla: 0,
                ins: INS_PUT,
                p1: otp_selector::SERIAL,
                p2: 0,
            };
            assert_eq!(state.execute(h, 256, &[], None, &mut p), Ok(Sw::SUCCESS));
            assert_eq!(&state.response[..4], &[1, 2, 3, 4]);
            assert_eq!(
                state.execute(Header { p2: 1, ..h }, 256, &[], None, &mut p),
                Err(Sw::WRONG_P1P2)
            );
            assert_eq!(
                state.execute(h, 256, &[0], None, &mut p),
                Err(Sw::WRONG_LENGTH)
            );
        }
    }
}
