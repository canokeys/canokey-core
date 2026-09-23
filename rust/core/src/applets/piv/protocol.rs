// SPDX-License-Identifier: Apache-2.0
//! Independent PIV adapter. APDU lifecycle and byte cursors belong to the runtime.

use super::wire::{
    ga_field, ga_tag, ins::*, key_tag, limits, metadata_tag, object_tlv, policy, reference,
    wire_alg,
};
use super::{codec, ga::Ga, import::Import, pin::Pins, repository as repo};
use crate::ports::alg;
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
pub const AID: &[u8] = &[
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
// Bounded ordinary request: RSA-4096 value plus one encoding byte.
pub const CAPACITY: usize = 513;
include!(concat!(env!("OUT_DIR"), "/piv_version.rs"));
// SELECT response: application template 61 contains the application suffix
// (4F) and an authority template 79 containing the five-byte PIV provider ID.
const SELECT: &[u8] = &[
    0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00,
    0x00, 0x03, 0x08,
];
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    External,
    Mutual,
}
#[derive(Clone, Copy, PartialEq, Eq)]
// Streaming GA order: optional SM2 identity, empty response tag, then payload.
// A field header advances this state before its value chunks are consumed.
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
// Response backing only; runtime::engine owns the GET RESPONSE byte cursor.
enum Response {
    Memory,
    Object(usize),
    Crypto(u8),
}
// Deferred public-key generation retains only routing metadata. Streaming
// initialization occurs after the current classic workspace borrow ends.
struct PendingPublicKey {
    slot_index: usize,
    include_metadata: bool,
}
pub struct Piv {
    pub(super) pins: Pins,
    // Management-key authentication grant, unrelated to the ADMIN applet PIN.
    admin: bool,
    // PIN_ALWAYS permits one private operation per successful PIN verification.
    pin_grant_consumed: bool,
    auth_mode: AuthMode,
    challenge: [u8; 16],
    config: [u8; 10],
    request: Request,
    response: Response,
    used: usize,
    // Large replies are header || generated/stored body || suffix. Only the
    // small wrappers live here; read_response pulls the body incrementally.
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
    pending_public: Option<PendingPublicKey>,
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
            pin_grant_consumed: false,
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
        self.pin_grant_consumed = false;
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
    fn metadata_header(&mut self, algorithm: u8, m: &[u8; repo::META]) -> usize {
        let prefix = [
            metadata_tag::ALGORITHM,
            1,
            repo::algorithm_id(algorithm, &self.config),
            metadata_tag::POLICY,
            2,
            m[repo::PIN_POLICY],
            m[repo::TOUCH_POLICY],
            metadata_tag::ORIGIN,
            1,
            m[repo::ORIGIN],
        ];
        self.header[..prefix.len()].copy_from_slice(&prefix);
        prefix.len()
    }
    pub fn supports_chaining(ins: u8) -> bool {
        matches!(
            ins,
            INS_GENERAL_AUTHENTICATE | INS_PUT_DATA | INS_IMPORT_KEY
        )
    }
    pub fn limit(h: Header) -> u32 {
        match h.ins {
            INS_PUT_DATA => limits::PUT_DATA_BYTES,
            INS_IMPORT_KEY => limits::KEY_IMPORT_BYTES,
            INS_GENERAL_AUTHENTICATE => limits::GENERAL_AUTHENTICATE_BYTES,
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
        // Only an SM2 GA continuation may retain the initiator exchange state.
        // Any other command reuses/clears the workspace and abandons that state.
        if h.ins == INS_GENERAL_AUTHENTICATE
            && repo::algorithm(h.p1, &self.config) == Ok(alg::SM2)
            && self.agreement.is_some()
        {
            p.memory.wipe(&mut w.key.bytes);
            p.memory.wipe(&mut w.input);
            p.memory.wipe(&mut w.output);
        } else {
            w.clear(p.memory);
            self.agreement = None;
        }
        if h.ins == INS_NAME && h.chained() {
            return Err(Sw::WRONG_LENGTH);
        }
        if h.ins != INS_GENERAL_AUTHENTICATE {
            self.auth_clear(p)
        }
        self.request = match h.ins {
            INS_GENERAL_AUTHENTICATE => {
                self.ga = Ga::new();
                Request::Ga
            }
            INS_IMPORT_KEY => {
                // IMPORT: P1 is the wire algorithm ID and P2 the destination
                // slot. F9 is the attestation signer and only accepts P-256.
                self.authorized()?;
                let id = repo::slot(h.p2)?;
                let a = repo::algorithm(h.p1, &self.config).map_err(|_| Sw::WRONG_P1P2)?;
                if id == repo::ATTESTATION_KEY && a != alg::P256 {
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
            INS_PUT_DATA => {
                // PUT DATA uses fixed P1/P2=3FFF; the 5C tag list in the body
                // selects the object. Management authorization precedes staging.
                self.authorized()?;
                if h.p1 != object_tlv::SELECT_P1 || h.p2 != object_tlv::SELECT_P2 {
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
                if self.import.meta[repo::ALGORITHM] < alg::MLKEM768 {
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
        if pin_policy != policy::PIN_NEVER
            && (!self.pins.state.pin_ok
                || (pin_policy == policy::PIN_ALWAYS && self.pin_grant_consumed))
        {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        self.pin_grant_consumed = true;
        Ok(())
    }
    fn touch(&mut self, policy: u8, p: &mut Platform<'_>) -> Result<(), Sw> {
        if policy < policy::TOUCH_ALWAYS {
            return Ok(());
        }
        let now = p.device.now();
        if policy == policy::TOUCH_CACHED
            && self
                .last_touch
                .is_some_and(|t| now.wrapping_sub(t) < policy::TOUCH_CACHE_MS)
        {
            return Ok(());
        }
        if !self.presence.wait(p.device) {
            return Err(Sw::EXECUTION_ERROR);
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
            INS_VERIFY => {
                let r = self.pins.verify(h, &w.input[..self.used], p);
                if r.is_ok() && (self.used == 8 || h.p1 == 0xff) {
                    self.pin_grant_consumed = false;
                }
                r
            }
            INS_CHANGE_REFERENCE_DATA => self.pins.change(h, &w.input[..self.used], p),
            INS_RESET_RETRY_COUNTER => self.pins.reset_retry(h, &w.input[..self.used], p),
            INS_GET_CHALLENGE | INS_GET_VERSION | INS_GET_SERIAL => {
                // These queries have no P1/P2 options; GET CHALLENGE takes its
                // requested byte count from Le, not either parameter byte.
                if h.p1 != 0x00 || h.p2 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                let n = match h.ins {
                    INS_GET_CHALLENGE => {
                        if le == 0 || le > 256 {
                            return Err(Sw::WRONG_LENGTH);
                        }
                        p.crypto
                            .random(&mut w.output[..le as usize])
                            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                        le as usize
                    }
                    INS_GET_VERSION => {
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
            INS_GET_DATA => self.get(h, w, p),
            INS_GENERAL_AUTHENTICATE => self.general_authenticate(h, w, p),
            INS_GENERATE_KEY => self.generate(h, w, p),
            INS_GET_METADATA => self.metadata(h, w, p),
            INS_NAME => self.name(h, w, p),
            INS_MOVE_KEY => self.move_key(h, p),
            INS_SET_MANAGEMENT_KEY => {
                // FF FF FE enables touch; FF FF FF disables touch. P1=FF is
                // the fixed key-replacement selector, not a destination slot.
                if h.p1 != 0xff || !matches!(h.p2, 0xfe | 0xff) {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 27 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if w.input[..3]
                    != [
                        wire_alg::AES192,
                        reference::MANAGEMENT,
                        repo::MANAGEMENT_KEY_BYTES as u8,
                    ]
                {
                    return Err(Sw::WRONG_DATA);
                }
                self.authorized()?;
                let mut m = repo::management_record(
                    if h.p2 == 0xfe {
                        policy::TOUCH_ALWAYS
                    } else {
                        policy::TOUCH_NEVER
                    },
                    &w.input[3..27],
                );
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
            INS_SET_RETRIES => {
                // P1/P2 are the new PIN/PUK retry limits (1..15), not selectors.
                // This command also resets both secrets and revokes grants.
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if !(0x01..=super::pin::MAX_RETRIES).contains(&h.p1)
                    || !(0x01..=super::pin::MAX_RETRIES).contains(&h.p2)
                {
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
            INS_RESET => {
                // FB 00 00 has no parameter modes; both credentials must be
                // blocked before this unauthenticated reset is permitted.
                if h.p1 != 0x00 || h.p2 != 0x00 {
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
            INS_CONFIG => {
                // CanoKey EE: P1=01 reads the algorithm mapping, P1=02 writes
                // it with management authorization. P2 is reserved (00).
                if h.p2 != 0x00 || !matches!(h.p1, 0x01 | 0x02) {
                    return Err(Sw::WRONG_P1P2);
                }
                if h.p1 == 0x01 {
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
        let a = codec::header(&mut self.header, &[ga_tag::TEMPLATE], n + inner)?;
        self.header_len = a + codec::header(&mut self.header[a..], &[ga_tag::RESPONSE], n)?;
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
