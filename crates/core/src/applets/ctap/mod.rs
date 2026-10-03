// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP parsing, PIN session and prepared responses for HID and APDU.
#![forbid(unsafe_code)]

mod agreement;
pub mod apdu;
mod attestation;
mod authentication;
mod client_pin;
mod config;
mod credential;
mod credential_request;
mod crypto;
mod encoding;
mod envelope;
mod hmac_secret;
mod info;
mod install;
mod large_blob;
mod management;
mod pin;
pub(crate) mod pq;
pub(crate) mod provision;
mod request_decoder;
mod resident;
pub(crate) mod settings;
pub mod u2f;
mod wire;

const MAKE_CREDENTIAL: u8 = 0x01;
const GET_ASSERTION: u8 = 0x02;
const NEXT_ASSERTION: u8 = 0x08;
const CREDENTIAL_MANAGEMENT: u8 = 0x0a;
const LEGACY_CREDENTIAL_MANAGEMENT: u8 = 0x41;
const LARGE_BLOBS: u8 = 0x0c;
const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;
const SELECTION: u8 = 0x0b;
const RESET: u8 = 0x07;
const CONFIG: u8 = 0x0d;
pub const MAX_REQUEST: usize = canokey_protocol::ctaphid::CTAP_MAX_REQUEST;
/// Response bytes are either immutable or in the sole session workspace.
/// Encoding happens once; transport retries only read the prepared result.
pub enum Response {
    Error(Status),
    Pending(pq::Pending),
    Stream(usize),
    Authentication {
        prefix: usize,
        auth: usize,
        certificate: Option<(usize, usize)>,
        total: usize,
    },
    Constant(&'static [u8]),
    Prepared(usize),
    Blob {
        offset: u32,
        length: usize,
        prefix: usize,
    },
}
impl Response {
    pub fn len(&self) -> usize {
        match self {
            Self::Error(_) => 1,
            Self::Pending(_) => 0,
            Self::Stream(n) => *n,
            Self::Authentication { total, .. } => *total,
            Self::Constant(bytes) => bytes.len(),
            Self::Prepared(n) => *n,
            Self::Blob { length, prefix, .. } => length + prefix,
        }
    }
    pub fn read(
        &self,
        workspace: &crate::runtime::workspace::Workspace,
        offset: usize,
        out: &mut [u8],
        storage: &mut crate::ports::StoragePort<'_>,
    ) -> Result<(), canokey_protocol::response::StatusWord> {
        use canokey_protocol::response::StatusWord as Sw;
        if let Self::Authentication {
            prefix,
            auth,
            certificate,
            total,
        } = *self
        {
            if !canokey_protocol::response::checked_window(offset, out.len(), total) {
                return Err(Sw::WRONG_LENGTH);
            }
            let cert_len = certificate.map_or(0, |(_, length)| length);
            let output_len = total - auth - cert_len;
            let split = certificate.map_or(output_len, |(at, _)| at);
            let segments = [
                &workspace.output[..prefix],
                &workspace.input[..auth],
                &workspace.output[prefix..split],
                &[],
                &workspace.output[split..output_len],
            ];
            let mut window = canokey_protocol::response::ReadWindow::new(offset, out);
            for (index, segment) in segments.iter().enumerate() {
                let length = if index == 3 { cert_len } else { segment.len() };
                let (start, dest) = window.take(length);
                if !dest.is_empty() {
                    if index == 3 {
                        storage
                            .read_at(crate::ports::Record::CtapCertificate, start as u32, dest)
                            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                    } else {
                        dest.copy_from_slice(&segment[start..start + dest.len()]);
                    }
                }
            }
            return Ok(());
        }
        if let Self::Blob {
            offset: start,
            length,
            prefix,
        } = *self
        {
            if !canokey_protocol::response::checked_window(offset, out.len(), prefix + length) {
                return Err(Sw::WRONG_LENGTH);
            }
            let head = out.len().min(prefix.saturating_sub(offset));
            if head != 0 {
                out[..head].copy_from_slice(&workspace.output[offset..offset + head]);
            }
            if head < out.len() {
                storage
                    .read_at(
                        crate::ports::Record::CtapLargeBlob,
                        start + (offset + head - prefix) as u32,
                        &mut out[head..],
                    )
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            }
            return Ok(());
        }
        let status;
        let bytes = match self {
            Self::Error(error) => {
                status = [*error as u8];
                &status[..]
            }
            Self::Constant(bytes) => bytes,
            Self::Prepared(n) => &workspace.output[..*n],
            Self::Blob { .. }
            | Self::Authentication { .. }
            | Self::Pending(_)
            | Self::Stream(_) => unreachable!(),
        };
        crate::applets::read_response_chunk(bytes, bytes.len(), offset, out)
    }
}

/// Small authorization state, independent of request and response buffers.
/// Private material is wiped on applet/session reset, never persisted.
pub struct Session {
    pub(crate) presence: crate::runtime::presence::Request,
    agreement: [u8; 32],
    agreement_ready: bool,
    pin_attempts: u8,
    token: [u8; 32],
    permissions: u8,
    token_started: u32,
    token_used: u32,
    rp_binding: [u8; 32],
    rp_bound: bool,
    assertion: resident::Assertion,
    management: management::Cursor,
    upload: large_blob::Upload,
    auth_response: Option<Response>,
    sm2: settings::Sm2,
}
impl Session {
    pub const fn new() -> Self {
        Self {
            presence: crate::runtime::presence::Request::new(),
            agreement: [0; 32],
            agreement_ready: false,
            pin_attempts: wire::pin_protocol::SESSION_ATTEMPTS,
            token: [0; 32],
            permissions: 0,
            token_started: 0,
            token_used: 0,
            rp_binding: [0; 32],
            rp_bound: false,
            assertion: resident::Assertion::new(),
            management: management::Cursor::new(),
            upload: large_blob::Upload::new(),
            auth_response: None,
            sm2: settings::Sm2::DEFAULT,
        }
    }
    pub fn reset(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        self.assertion.remaining = 0;
        self.assertion.hmac.clear(memory);
        self.management = management::Cursor::new();
        memory.wipe(&mut self.assertion.client_hash);
        memory.wipe(&mut self.agreement);
        self.agreement_ready = false;
        self.clear_token(memory);
    }
    pub fn execute(
        &mut self,
        command: &mut Result<Command, Status>,
        workspace: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Response {
        self.expire_token(p.device.now(), p.memory);
        self.auth_response = None;
        // Classify once. Parse failures invalidate every continuation too.
        const ASSERTION: u8 = 1;
        const MANAGEMENT: u8 = 2;
        const BLOB: u8 = 4;
        const SM2: u8 = 8;
        let policy = match command {
            Ok(Command::NextAssertion) => ASSERTION,
            Ok(Command::Management(_)) => MANAGEMENT | SM2,
            Ok(Command::LargeBlob(_)) => BLOB,
            Ok(Command::Credential(_) | Command::GetInfo) => SM2,
            _ => 0,
        };
        if policy & ASSERTION == 0 {
            self.assertion.remaining = 0;
            self.assertion.hmac.clear(p.memory);
        }
        if policy & MANAGEMENT == 0 {
            self.management = management::Cursor::new();
        }
        if policy & BLOB == 0 {
            self.abort_blob(p);
        }
        if policy & SM2 != 0 {
            match settings::Sm2::load(p) {
                Ok(config) => self.sm2 = config,
                Err(error) => {
                    self.reset(p.memory);
                    return Response::Error(error);
                }
            }
        }
        let result = match &mut *command {
            Ok(Command::Wink) => {
                p.device.wink();
                Ok(0)
            }
            Ok(Command::NextAssertion) => self.credential(None, workspace, p),
            Ok(Command::Reset) => self.reset_data(workspace, p),
            Ok(Command::Selection) => self.selection(workspace, p),
            Ok(Command::GetInfo) => self.info(workspace, p),
            Ok(Command::GetPinRetries) => self.retries(workspace, p),
            Ok(Command::Credential(params)) => {
                params.algorithm =
                    params.algorithms[..params.algorithm_count]
                        .iter()
                        .find_map(|id| match *id {
                            wire::cose::ES256 => Some(crate::ports::alg::P256),
                            wire::cose::EDDSA => Some(crate::ports::alg::ED25519),
                            wire::cose::MLDSA65
                                if credential::permitted(crate::ports::alg::MLDSA65) =>
                            {
                                Some(crate::ports::alg::MLDSA65)
                            }
                            n if n == self.sm2.algorithm
                                && credential::permitted(crate::ports::alg::SM2) =>
                            {
                                Some(crate::ports::alg::SM2)
                            }
                            _ => None,
                        });
                self.credential(Some(params), workspace, p)
            }
            Ok(Command::LargeBlob(params)) => self.large_blob(params, workspace, p),
            Ok(Command::Management(params)) => self.manage(params, workspace, p),
            Ok(Command::Config(params)) => self.configure(params, workspace, p),
            Ok(Command::ClientPin(params)) => self.client_pin(params, workspace, p),
            Ok(Command::GetKeyAgreement) => self.key_agreement(workspace, p),
            Err(status) => Err(*status),
        };
        // An uncertain commit may already have changed the PIN. Never retain
        // authorization from before a persistence/primitive failure.
        if matches!(result, Err(Status::Other)) {
            self.reset(p.memory);
        }
        match result {
            Ok(n) => {
                if let Some(response) = self.auth_response.take() {
                    return response;
                }
                Response::Prepared(n)
            }
            Err(status) => Response::Error(status),
        }
    }
    fn reset_data(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        // Match the C power-on window; transport resets must not restart it.
        if p.device.now() > 10_000 {
            return Err(Status::NotAllowed);
        }
        let long = pin::policy(p)?.flags & pin::LONG_RESET != 0;
        self.wait_presence(w, p, long)?;
        self.erase(p)?;
        Ok(1)
    }
    fn erase(&mut self, p: &mut crate::ports::Platform<'_>) -> Result<(), Status> {
        self.abort_blob(p);
        self.reset(p.memory);
        // Provisioned attestation material and SM2 identifiers survive reset.
        for record in [
            crate::ports::Record::CtapMaster,
            crate::ports::Record::CtapCounter,
            crate::ports::Record::CtapPin,
            crate::ports::Record::CtapLargeBlob,
        ] {
            p.storage.remove(record).map_err(|_| Status::Other)?;
        }
        for index in 0..crate::ports::Record::CTAP_GROUPS {
            p.storage
                .remove(crate::ports::Record::ctap_group(index).unwrap())
                .map_err(|_| Status::Other)?;
        }
        self.pin_attempts = wire::pin_protocol::SESSION_ATTEMPTS;
        Ok(())
    }
    fn selection(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        self.wait_presence(w, p, false)
    }
    fn wait_presence(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
        long: bool,
    ) -> Result<usize, Status> {
        p.device.keepalive(true);
        p.device.led(true);
        let result = if long {
            self.presence.wait_long(p.device)
        } else {
            self.presence.wait_result(p.device)
        };
        p.device.led(false);
        p.device.keepalive(false);
        result.map_err(|error| match error {
            crate::runtime::presence::Error::Cancelled => Status::Cancelled,
            crate::runtime::presence::Error::Timeout => Status::UserActionTimeout,
        })?;
        w.output[0] = 0;
        Ok(1)
    }
    #[inline(never)]
    fn info(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        let policy = pin::policy(p)?;
        w.output[0] = 0;
        let used = resident::count(w.input, p)?;
        info::encode(
            &mut w.output[1..],
            policy.flags,
            policy.pin_length != 0,
            policy.minimum,
            used,
            self.sm2.algorithm,
        )
        .map(|n| n + 1)
        .map_err(|_| Status::Other)
    }

    fn key_agreement(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        use crate::ports::{KeyOperation, alg};
        w.clear(p.memory);
        let result = (|| {
            self.agreement_key(w, p)?;
            let n = p
                .crypto
                .key_operation(KeyOperation::Public, alg::P256, &mut w.key, &[], w.input)
                .map_err(|_| Status::Other)?;
            if n != 64 {
                return Err(Status::Other);
            }
            Ok(encoding::key_agreement(
                w.output,
                (&w.input[..64]).try_into().unwrap(),
            ))
        })();
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(w.input);
        if result.is_err() {
            self.reset(p.memory);
            p.memory.wipe(w.output);
        }
        result
    }
}

pub enum Command {
    Wink,
    LargeBlob(large_blob::Parameters),
    NextAssertion,
    Reset,
    Selection,
    GetInfo,
    GetPinRetries,
    GetKeyAgreement,
    ClientPin(client_pin::Parameters),
    Config(envelope::Parameters),
    Management(envelope::Parameters),
    Credential(credential_request::Parameters),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    LargeBlobFull = 0x18,
    IntegrityFailure = 0x3d,
    InvalidSequence = 0x04,
    UnsupportedAlgorithm = 0x26,
    NoCredentials = 0x2e,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    CredentialExcluded = 0x19,
    OperationDenied = 0x27,
    LimitExceeded = 0x15,
    PuatRequired = 0x36,
    KeyStoreFull = 0x28,
    NotAllowed = 0x30,
    Cancelled = 0x2d,
    UserActionTimeout = 0x2f,
    UnauthorizedPermission = 0x40,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PinPolicy = 0x37,
    Other = 0x7f,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    UnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    InvalidSubcommand = 0x3e,
    UnhandledRequest = 0xf1,
}

pub struct Request {
    command: Option<u8>,
    extra: bool,
    parser: Parser,
}
impl Request {
    pub const fn new() -> Self {
        Self {
            command: None,
            extra: false,
            parser: Parser::None,
        }
    }
    pub fn consume(&mut self, mut bytes: &[u8]) {
        if self.command.is_none() {
            self.command = bytes.first().copied();
            bytes = bytes.get(1..).unwrap_or_default();
            self.parser.initialize(self.command);
        }
        match &mut self.parser {
            Parser::ClientPin(parser) => parser.consume(bytes),
            Parser::Config(parser) => parser.consume(bytes),
            Parser::LargeBlob(parser) => parser.consume(bytes),
            Parser::Credential(parser) => parser.consume(bytes),
            Parser::None => self.extra |= !bytes.is_empty(),
        }
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        match &mut self.parser {
            Parser::ClientPin(p) => p.clear(memory),
            Parser::Config(p) => p.clear(memory),
            Parser::LargeBlob(p) => p.clear(memory),
            Parser::Credential(p) => p.clear(memory),
            Parser::None => {}
        }
        self.command = None;
        self.extra = false;
        self.parser = Parser::None;
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        match self.command.take() {
            None => Err(Status::InvalidLength),
            Some(NEXT_ASSERTION) if !self.extra => Ok(Command::NextAssertion),
            Some(NEXT_ASSERTION) => Err(Status::InvalidLength),
            Some(RESET) if !self.extra => Ok(Command::Reset),
            Some(RESET) => Err(Status::InvalidLength),
            Some(SELECTION) if !self.extra => Ok(Command::Selection),
            Some(SELECTION) => Err(Status::InvalidLength),
            Some(GET_INFO) if !self.extra => Ok(Command::GetInfo),
            Some(GET_INFO) => Err(Status::InvalidLength),
            Some(
                MAKE_CREDENTIAL
                | GET_ASSERTION
                | CLIENT_PIN
                | CONFIG
                | CREDENTIAL_MANAGEMENT
                | LEGACY_CREDENTIAL_MANAGEMENT
                | LARGE_BLOBS,
            ) => match &mut self.parser {
                Parser::ClientPin(parser) => parser.finish(),
                Parser::Config(parser) => parser.finish(),
                Parser::LargeBlob(parser) => parser.finish(),
                Parser::Credential(parser) => parser.finish(),
                Parser::None => Err(Status::InvalidCbor),
            },
            _ => Err(Status::UnhandledRequest),
        }
    }
}

// Command schemas alias the single session workspace, never parallel buffers.
enum Parser {
    None,
    ClientPin(client_pin::Parser),
    Config(envelope::Parser),
    LargeBlob(large_blob::Parser),
    Credential(credential_request::Parser),
}

impl Parser {
    // Variants initialize in place: a const template would materialize one
    // full-enum-sized rodata copy per arm, while
    // the transient construction stack frame is freed before any crypto runs.
    // Commands sharing a schema also share its construction path; only the
    // command-specific mode changes, not the initialized parser state.
    #[inline(never)]
    fn initialize(&mut self, command: Option<u8>) {
        match command {
            Some(CLIENT_PIN) => *self = Self::ClientPin(client_pin::Parser::new()),
            Some(command @ (CREDENTIAL_MANAGEMENT | LEGACY_CREDENTIAL_MANAGEMENT | CONFIG)) => {
                *self = Self::Config(envelope::Parser::new(command))
            }
            Some(LARGE_BLOBS) => *self = Self::LargeBlob(large_blob::Parser::new()),
            Some(command @ (MAKE_CREDENTIAL | GET_ASSERTION)) => {
                *self =
                    Self::Credential(credential_request::Parser::new(command == MAKE_CREDENTIAL))
            }
            _ => *self = Self::None,
        }
    }
}

// Integer keys sort by (negative, argument): nonnegative keys before negative.
// This is not length-first canonical CBOR ordering across encoded widths.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    negative: bool,
    argument: u64,
}
impl Key {
    // Preserve the full 64-bit ordering even for unrecognized field labels.
    // One call boundary avoids duplicating the comparison in every schema.
    // None is an unknown label, not an absent key; callers retain it as Some(None).
    #[inline(never)]
    fn ordered(
        event: &canokey_protocol::cbor::Event<'_>,
        previous: &mut Option<Self>,
    ) -> Result<Option<i8>, Status> {
        let key = Self::parse(event)?;
        if previous.is_some_and(|old| key <= old) {
            return Err(Status::InvalidCbor);
        }
        *previous = Some(key);
        Ok(key.integer())
    }
    fn parse(event: &canokey_protocol::cbor::Event<'_>) -> Result<Self, Status> {
        match *event {
            canokey_protocol::cbor::Event::Unsigned(argument) => Ok(Self {
                negative: false,
                argument,
            }),
            canokey_protocol::cbor::Event::Negative(argument) => Ok(Self {
                negative: true,
                argument,
            }),
            _ => Err(Status::UnexpectedType),
        }
    }
    fn integer(self) -> Option<i8> {
        let n = i8::try_from(self.argument).ok()?;
        Some(if self.negative { -1 - n } else { n })
    }
}

#[inline]
pub(super) fn is_cbor_container(event: &canokey_protocol::cbor::Event<'_>) -> bool {
    matches!(
        event,
        canokey_protocol::cbor::Event::Map(_)
            | canokey_protocol::cbor::Event::Array(_)
            | canokey_protocol::cbor::Event::Bytes(_)
            | canokey_protocol::cbor::Event::Text(_)
    )
}

/// Consume one event while ignoring an unsupported CBOR value. The decoder
/// emits container starts and a matching End, so all extension parsers can use
/// the same depth transition rules.
pub(super) fn skip_cbor_event(depth: &mut u8, event: &canokey_protocol::cbor::Event<'_>) -> bool {
    if *depth == 0 {
        return false;
    }
    if is_cbor_container(event) {
        *depth = depth.saturating_add(1);
    } else if matches!(event, canokey_protocol::cbor::Event::End) {
        *depth -= 1;
    }
    true
}

pub(super) fn consume_cbor_body(
    event: &canokey_protocol::cbor::Event<'_>,
    body: &mut Option<(i8, usize)>,
    target: &mut [u8],
) -> Result<(), Status> {
    let Some((key, offset)) = *body else {
        return Err(Status::Other);
    };
    match *event {
        canokey_protocol::cbor::Event::Data(bytes) => {
            let end = offset.checked_add(bytes.len()).ok_or(Status::InvalidCbor)?;
            target
                .get_mut(offset..end)
                .ok_or(Status::InvalidCbor)?
                .copy_from_slice(bytes);
            *body = Some((key, end));
        }
        canokey_protocol::cbor::Event::End => *body = None,
        _ => return Err(Status::InvalidCbor),
    }
    Ok(())
}
