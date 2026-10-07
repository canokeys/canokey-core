// SPDX-License-Identifier: Apache-2.0
//! OATH wire schema. Domain/authentication modules have no APDU dependency.
#![forbid(unsafe_code)]

#[cfg(test)]
use super::wire::otp_selector;
use super::{
    legacy_otp,
    wire::{ins::*, tag},
};
use crate::applets::oath::{
    Algorithm, Crypto, Error, auth, credential,
    credential::{Credential, Kind, Properties},
    service::{self, Presence, Repository},
};
#[cfg(test)]
use crate::applets::pass::domain::Slot;
use crate::applets::pass::domain::SlotIndex;
use crate::flows::oath_pass;
use crate::{
    Platform,
    applets::oath::repository::{Mac, Store},
    applets::pass::service::Pass,
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw, tlv::ByteCursor};
mod paging;
include!(concat!(env!("OUT_DIR"), "/oath_version.rs"));
// Yubico RID A000000527, OATH application suffix 2101.
pub const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
pub const CAPACITY: usize = 288;
const NAME_LIMIT: usize = credential::NAME_LIMIT;
const CHALLENGE_LIMIT: usize = auth::CHALLENGE_BYTES;
const KEY_HEADER_BYTES: usize = 2;
const OATH_KEY_LIMIT: usize = credential::KEY_LIMIT;
const SET_CODE_KEY_BYTES: usize = 1 + 16;
const SET_CODE_ALGORITHM: u8 = 0x01;
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
fn workflow_status(error: oath_pass::Error) -> Sw {
    match error {
        oath_pass::Error::Oath(error) => status(error),
        oath_pass::Error::Pass(error) => crate::applets::pass::status(error),
        oath_pass::Error::NotHotp => Sw::CONDITIONS_NOT_SATISFIED,
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
    response: [u8; canokey_protocol::apdu::SHORT_DATA_BYTES],
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
            response: [0; canokey_protocol::apdu::SHORT_DATA_BYTES],
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
                0x01, // One-byte SELECT challenge MAC algorithm.
                Algorithm::Sha1 as u8,
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
        // OATH PUT KEY encodes kind/algorithm, digits, then secret material.
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
            drop(store);
            drop(mac);
            oath_pass::delete(old, pass, p).map_err(workflow_status)?;
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
            // Access-code proofs use a host nonce, not the bounded TOTP counter.
            let challenge = field(&mut c, tag::CHALLENGE)?;
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
        let metadata = store.metadata(id).map_err(status)?;
        let kind = metadata.kind;
        let touch = metadata.properties.touch();
        let input = if kind == Kind::Totp {
            challenge(&mut c)?
        } else {
            &[]
        };
        // HOTP ignores a client-supplied timestamp (as the legacy applet did).
        if kind == Kind::Totp && !c.is_empty() {
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
        // P1=1/2 selects a PASS slot (one-based); P2=0/1 controls
        // the trailing Enter key. NAME binds an HOTP credential.
        let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
        if !(0x01..=0x02).contains(&h.p1) || h.p2 > 0x01 {
            return Err(Sw::WRONG_P1P2);
        }
        let name = name(&mut c)?;
        oath_pass::bind(pass, SlotIndex::new(h.p1 - 1).unwrap(), name, h.p2, p)
            .map_err(workflow_status)
    }

    // Keep command dispatch separate from finish-time wiping and error cleanup.
    // This boundary reduces code size in the full DevKit and NFCC images
    // with the pinned optimizer.
    #[inline(never)]
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
        if legacy_otp::matches(h) {
            self.length = legacy_otp::execute(h, data, pass, p, &mut self.response)?;
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
    pub fn take_presence_attempt(&mut self) -> bool {
        self.state.presence.take_attempt()
    }
    pub fn cancel_command(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.command);
        self.used = 0;
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        crate::applets::append_bounded(&mut self.used, &mut self.command, CAPACITY, bytes)
            .ok_or(Sw::WRONG_LENGTH)?;
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
        // Preserve one local state base at this call boundary. On CIU, LTO's
        // specialization to CORE otherwise expands repeated field addresses.
        // This is a measured code-size barrier, not a security boundary.
        let result = core::hint::black_box(&mut self.state).execute(
            h,
            le,
            &self.command[..self.used],
            pass,
            p,
        );
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

    struct BindingStore {
        oath: [u8; 8 + super::super::codec::LENGTH],
        pass: [u8; crate::applets::pass::codec::FILE_SIZE],
        writes: usize,
        fail_write: bool,
    }
    impl BindingStore {
        fn new(name: &[u8], kind: Kind) -> Self {
            let mut store = Self {
                oath: [0; 8 + super::super::codec::LENGTH],
                pass: [0; crate::applets::pass::codec::FILE_SIZE],
                writes: 0,
                fail_write: false,
            };
            store.oath[..8].copy_from_slice(b"OAT2\x00\x00\x00\x07");
            let mut credential = Credential::new(
                name,
                &[0x5a; 64],
                kind,
                Algorithm::Sha1,
                6,
                Properties::new(2).unwrap(),
                [0; 8],
            )
            .unwrap();
            super::super::codec::encode(&credential, (&mut store.oath[8..]).try_into().unwrap());
            credential.clear(&mut Mac::new(&mut NoMac, &Wipe));
            store
        }
    }
    impl Storage for BindingStore {
        fn load(&mut self, record: Record, _: &mut [u8]) -> Result<usize, StorageError> {
            assert_eq!(record, Record::Pass);
            Err(StorageError::Missing)
        }
        fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError> {
            assert_eq!(record, Record::Pass);
            self.pass.copy_from_slice(input);
            Ok(())
        }
        fn replace_at(
            &mut self,
            record: Record,
            at: u32,
            input: &[u8],
        ) -> Result<(), StorageError> {
            assert_eq!(record, Record::Pass);
            self.writes += 1;
            self.pass[at as usize..at as usize + input.len()].copy_from_slice(input);
            if self.fail_write {
                Err(StorageError::Uncertain)
            } else {
                Ok(())
            }
        }
        fn size(&mut self, record: Record) -> Result<u32, StorageError> {
            assert_eq!(record, Record::OathRecords);
            Ok(self.oath.len() as u32)
        }
        fn read_at(&mut self, record: Record, at: u32, out: &mut [u8]) -> Result<(), StorageError> {
            assert_eq!(record, Record::OathRecords);
            let end = at as usize + out.len();
            assert!(
                end <= 8 + super::super::codec::KEY_OFFSET,
                "SET_DEFAULT read a key"
            );
            out.copy_from_slice(&self.oath[at as usize..end]);
            Ok(())
        }
    }

    #[test]
    fn set_default_binds_exact_name_without_reading_secrets_or_waiting_for_touch() {
        for name in [&b"h"[..], &[b'n'; NAME_LIMIT][..]] {
            for slot in 1..=2 {
                let mut storage = BindingStore::new(name, Kind::Hotp);
                let mut pass = Pass::new();
                pass.install(&mut storage, &Wipe).unwrap();
                let mut wire = [0; 2 + NAME_LIMIT];
                wire[..2].copy_from_slice(&[tag::NAME, name.len() as u8]);
                wire[2..2 + name.len()].copy_from_slice(name);
                let h = Header {
                    cla: 0,
                    ins: INS_SET_DEFAULT,
                    p1: slot,
                    p2: slot - 1,
                };
                let mut state = State::new();
                for fail in [false, true] {
                    storage.fail_write = fail;
                    let result = state.execute_set_default(
                        h,
                        &mut ByteCursor::new(&wire[..2 + name.len()]),
                        Some(&mut pass),
                        &mut Platform {
                            storage: &mut storage,
                            crypto: &mut NoMac,
                            device: &mut NoPresence,
                            memory: &Wipe,
                        },
                    );
                    if fail {
                        assert_eq!(
                            result,
                            Err(crate::applets::pass::status(
                                crate::applets::pass::domain::Error::Persistence
                            ))
                        );
                        assert!(pass.records().is_err());
                    } else {
                        assert_eq!(result, Ok(()));
                        assert!(matches!(pass.slot(slot - 1), Ok(Slot::Oath {
                            id: 7, name: stored, enter,
                        }) if stored == name && enter == slot - 1));
                        assert_eq!(pass.records().unwrap(), &storage.pass);
                    }
                }
                assert_eq!(storage.writes, 2);
            }
        }
    }

    #[test]
    fn set_default_rejects_missing_totp_and_corrupt_metadata_without_writes() {
        for (name, kind, corrupt, expected) in [
            (b'x', Kind::Hotp, false, Sw::DATA_INVALID),
            (b'h', Kind::Totp, false, Sw::CONDITIONS_NOT_SATISFIED),
            (b'h', Kind::Hotp, true, Sw::WRONG_DATA),
        ] {
            let mut storage = BindingStore::new(b"h", kind);
            if corrupt {
                storage.oath[8 + 4] = 9;
            } // Invalid digits.
            let mut pass = Pass::new();
            pass.install(&mut storage, &Wipe).unwrap();
            assert_eq!(
                State::new().execute_set_default(
                    Header {
                        cla: 0,
                        ins: INS_SET_DEFAULT,
                        p1: 1,
                        p2: 0
                    },
                    &mut ByteCursor::new(&[tag::NAME, 1, name]),
                    Some(&mut pass),
                    &mut Platform {
                        storage: &mut storage,
                        crypto: &mut NoMac,
                        device: &mut NoPresence,
                        memory: &Wipe
                    },
                ),
                Err(expected)
            );
            assert_eq!(storage.writes, 0);
            assert!(matches!(pass.slot(0), Ok(Slot::Off)));
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
