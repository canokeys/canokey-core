// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP parsing, PIN session and prepared responses for HID and APDU.
#![forbid(unsafe_code)]

use canokey_ports::{Crypto as _, Device as _, Memory as _, Storage as _};
mod adapter;
mod agreement;
mod applet;
pub use applet::Applet;
pub mod apdu;
mod attestation;
mod authentication;
#[cfg(test)]
mod cbor_skip_tests;
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
pub mod message;
mod pin;
pub(crate) mod pq;
pub(crate) mod provision;
mod request_decoder;
mod resident;
#[cfg(test)]
mod response_tests;
pub(crate) mod settings;
pub mod u2f;
mod wire;

const MAKE_CREDENTIAL: u8 = canokey_ctap::config::Command::MakeCredential as u8;
const GET_ASSERTION: u8 = canokey_ctap::config::Command::GetAssertion as u8;
const CREDENTIAL_MANAGEMENT: u8 = canokey_ctap::config::Command::CredentialManagement as u8;
const LEGACY_CREDENTIAL_MANAGEMENT: u8 =
    canokey_ctap::config::Command::LegacyCredentialManagement as u8;
const LARGE_BLOBS: u8 = canokey_ctap::config::Command::LargeBlobs as u8;
#[cfg(test)]
const GET_INFO: u8 = canokey_ctap::config::Command::GetInfo as u8;
const CLIENT_PIN: u8 = canokey_ctap::config::Command::ClientPin as u8;
const CONFIG: u8 = canokey_ctap::config::Command::Config as u8;
pub const MAX_REQUEST: usize = crate::config::CTAP_MAX_REQUEST;
// C's source-backed APDU output uses250 bytes, independently of the short
// buffer's256-byte capacity. Native HID can send a complete source directly.
const APDU_STREAM_CHUNK: usize = 250;
const APDU_BUFFER_BYTES: usize = 256;
/// Response bytes are either immutable or in the sole session workspace.
/// Encoding happens once; transport retries only read the prepared result.
pub enum Response {
    Error(Status),
    Pending(pq::Pending),
    Stream(usize),
    Authentication {
        // U2F ISO registration permits partial certificate progress; generic
        // CTAP segments and native HID still require exact reads.
        registration: bool,
        prefix: usize,
        auth: usize,
        certificate: Option<(usize, usize)>,
        total: usize,
    },
    Constant(&'static [u8]),
    Prepared(usize),
    MemoryStream(usize),
    Blob {
        offset: u32,
        length: usize,
        prefix: usize,
    },
}
impl Response {
    #[inline(never)]
    pub fn len(&self) -> usize {
        match self {
            Self::Error(_) => 1,
            Self::Pending(_) => 0,
            Self::Stream(n) => *n,
            Self::Authentication { total, .. } => *total,
            Self::Constant(bytes) => bytes.len(),
            Self::Prepared(n) | Self::MemoryStream(n) => *n,
            Self::Blob { length, prefix, .. } => length + prefix,
        }
    }
    // Share this decision across ISO/native output; outlining saves product ROM.
    #[inline(never)]
    fn source_backed(&self) -> bool {
        // Ordinary CBOR becomes a memory source above the short buffer limit.
        // Attested MC and U2F REGISTER use a source even when they fit it.
        match self {
            Self::MemoryStream(_) | Self::Stream(_) | Self::Blob { .. } => true,
            Self::Authentication {
                certificate: Some(_),
                ..
            } => true,
            Self::Authentication { total, .. } | Self::Prepared(total) => {
                *total > APDU_BUFFER_BYTES
            }
            _ => false,
        }
    }
    fn apdu_chunk(&self, length: usize) -> usize {
        if self.source_backed() {
            length.min(APDU_STREAM_CHUNK)
        } else {
            length
        }
    }
    pub fn read(
        &self,
        workspace: &crate::runtime::workspace::Workspace,
        offset: usize,
        out: &mut [u8],
        storage: &mut (impl crate::ports::Storage + ?Sized),
    ) -> Result<(), canokey_protocol::response::StatusWord> {
        self.read_window(workspace, offset, out, storage, false)
            .map(|_| ())
    }
    fn read_window(
        &self,
        workspace: &crate::runtime::workspace::Workspace,
        offset: usize,
        out: &mut [u8],
        storage: &mut (impl crate::ports::Storage + ?Sized),
        partial: bool,
    ) -> Result<usize, canokey_protocol::response::StatusWord> {
        use canokey_protocol::response::StatusWord as Sw;
        if let Self::Authentication {
            registration,
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
            let mut copied = 0;
            for (index, segment) in segments.iter().enumerate() {
                let length = if index == 3 { cert_len } else { segment.len() };
                let (start, dest) = window.take(length);
                if !dest.is_empty() {
                    if index == 3 {
                        use canokey_ctap::response::{self, ReadMode};
                        let mode = if partial && registration {
                            ReadMode::Partial
                        } else {
                            ReadMode::Exact
                        };
                        let count = response::certificate(
                            &mut adapter::Certificate(storage),
                            start as u32,
                            dest,
                            mode,
                        )
                        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                        if count < dest.len() {
                            return Ok(copied + count);
                        }
                    } else {
                        dest.copy_from_slice(&segment[start..start + dest.len()]);
                    }
                }
                copied += dest.len();
            }
            return Ok(copied);
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
            return Ok(out.len());
        }
        let status;
        let bytes = match self {
            Self::Error(error) => {
                status = [*error as u8];
                &status[..]
            }
            Self::Constant(bytes) => bytes,
            Self::Prepared(n) | Self::MemoryStream(n) => &workspace.output[..*n],
            Self::Blob { .. }
            | Self::Authentication { .. }
            | Self::Pending(_)
            | Self::Stream(_) => unreachable!(),
        };
        crate::applets::read_response_chunk(bytes, bytes.len(), offset, out).map(|()| out.len())
    }
}

/// Small authorization state, independent of request and response buffers.
/// Private material is wiped on applet/session reset, never persisted.
// Keep the PIN owner at the front for compact Thumb-1 field addressing. This
// explicit volatile layout is neither serialized nor exposed through a C ABI.
#[repr(C)]
pub struct Session {
    pin: canokey_ctap::client_pin::Session<u8>,
    pub(crate) presence: crate::runtime::presence::Request,
    pin_attempts: canokey_ctap::client_pin::retry::Attempts,
    sm2: settings::Sm2,
    upload: large_blob::Upload,
    management: management::Cursor,
    assertion: resident::Assertion,
    auth_response: Option<Response>,
}
impl Session {
    pub const fn new() -> Self {
        Self {
            pin: canokey_ctap::client_pin::Session::empty(0x00),
            presence: crate::runtime::presence::Request::new(),
            pin_attempts: canokey_ctap::client_pin::retry::Attempts::new(),
            sm2: settings::Sm2::DEFAULT,
            upload: large_blob::Upload::new(),
            management: management::Cursor::new(),
            assertion: resident::Assertion::new(),
            auth_response: None,
        }
    }
    pub fn reset(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        self.assertion.remaining = 0;
        self.assertion.hmac.clear(memory);
        self.management = management::Cursor::new();
        memory.wipe(&mut self.assertion.client_hash);
        self.pin.clear(|bytes| memory.wipe(bytes));
    }
    pub fn execute(
        &mut self,
        command: &mut Result<Command, Status>,
        workspace: &mut crate::runtime::workspace::SessionWorkspace,
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
    ) -> Response {
        let mut classic = workspace.classic_with(p.memory);
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
            match settings::load(p) {
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
            Ok(Command::Reset) => self.reset_data(&mut classic, p),
            Ok(Command::Selection) => self.selection(&mut classic, p),
            Ok(Command::GetInfo) => self.info(&mut classic, p),
            Ok(Command::GetPinRetries) => self.retries(&mut classic, p),
            Ok(Command::Credential(params)) => {
                params.algorithm =
                    params.algorithms[..params.algorithm_count]
                        .iter()
                        .find_map(|id| match *id {
                            wire::cose::ES256 => Some(crate::ports::alg::P256),
                            wire::cose::EDDSA => Some(crate::ports::alg::ED25519),
                            n if n == self.sm2.algorithm
                                && credential::permitted(crate::ports::alg::SM2) =>
                            {
                                Some(crate::ports::alg::SM2)
                            }
                            n => crate::ports::mldsa::from_cose(n)
                                .filter(|p| credential::permitted(p.algorithm))
                                .map(|p| p.algorithm),
                        });
                self.credential(Some(params), workspace, p)
            }
            Ok(Command::LargeBlob(params)) => self.large_blob(params, &mut classic, p),
            Ok(Command::Management(params)) => self.manage(params, &mut classic, p),
            Ok(Command::Config(params)) => self.configure(params, &mut classic, p),
            Ok(Command::ClientPin(params)) => self.client_pin(params, &mut classic, p),
            Ok(Command::GetKeyAgreement) => self.key_agreement(&mut classic, p),
            Err(status) => Err(*status),
        };
        // An uncertain commit may already have changed the PIN. Never retain
        // authorization from before a persistence/primitive failure.
        if result
            .as_ref()
            .is_err_and(|status| canokey_ctap::session::reset_on_error(*status as u8))
        {
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
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        // Match the C power-on window; transport resets must not restart it.
        if p.device.now() > 10_000 {
            return Err(Status::NotAllowed);
        }
        let long = pin::policy(p)?.flags & pin::LONG_RESET != 0;
        self.wait_presence(w, p, long)?;
        self.reset_persistent(p)?;
        Ok(1)
    }
    fn reset_persistent(
        &mut self,
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
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
        self.pin_attempts.reset();
        Ok(())
    }
    fn selection(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        self.wait_presence(w, p, false)
    }
    fn wait_presence(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
        long: bool,
    ) -> Result<usize, Status> {
        p.device.keepalive(true);
        let result = if long {
            self.presence.wait_long(p.device)
        } else {
            self.presence.wait_result(p.device)
        };
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
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let policy = pin::policy(p)?;
        w.output[0] = 0;
        let used = resident::count(w.input, p)?;
        let n = info::encode(
            &mut w.output[1..],
            policy.flags,
            policy.pin_length != 0,
            policy.minimum,
            used,
            self.sm2.algorithm,
        )
        .map(|n| n + 1)
        .map_err(|_| Status::Other)?;
        self.auth_response = Some(Response::MemoryStream(n));
        Ok(n)
    }

    fn key_agreement(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_, impl crate::ports::Backends>,
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
    LargeBlobFull = canokey_ctap::status::Status::LargeBlobFull as u8,
    IntegrityFailure = canokey_ctap::status::Status::IntegrityFailure as u8,
    InvalidSequence = canokey_ctap::status::Status::InvalidSequence as u8,
    UnsupportedAlgorithm = canokey_ctap::status::Status::UnsupportedAlgorithm as u8,
    NoCredentials = canokey_ctap::status::Status::NoCredentials as u8,
    UnsupportedOption = canokey_ctap::status::Status::UnsupportedOption as u8,
    InvalidOption = canokey_ctap::status::Status::InvalidOption as u8,
    CredentialExcluded = canokey_ctap::status::Status::CredentialExcluded as u8,
    OperationDenied = canokey_ctap::status::Status::OperationDenied as u8,
    LimitExceeded = canokey_ctap::status::Status::LimitExceeded as u8,
    PuatRequired = canokey_ctap::status::Status::PuatRequired as u8,
    KeyStoreFull = canokey_ctap::status::Status::NoSpace as u8,
    NotAllowed = canokey_ctap::status::Status::NotAllowed as u8,
    Cancelled = canokey_ctap::status::Status::KeepaliveCancel as u8,
    UserActionTimeout = canokey_ctap::status::Status::UserActionTimeout as u8,
    UnauthorizedPermission = canokey_ctap::status::Status::UnauthorizedPermission as u8,
    PinInvalid = canokey_ctap::status::Status::PinInvalid as u8,
    PinBlocked = canokey_ctap::status::Status::PinBlocked as u8,
    PinAuthInvalid = canokey_ctap::status::Status::PinAuthInvalid as u8,
    PinAuthBlocked = canokey_ctap::status::Status::PinAuthBlocked as u8,
    PinNotSet = canokey_ctap::status::Status::PinNotSet as u8,
    PinPolicy = canokey_ctap::status::Status::PinPolicyViolation as u8,
    Other = canokey_ctap::status::Status::Internal as u8,
    InvalidCommand = canokey_ctap::status::Status::InvalidCommand as u8,
    InvalidParameter = canokey_ctap::status::Status::InvalidParameter as u8,
    InvalidLength = canokey_ctap::status::Status::InvalidLength as u8,
    UnexpectedType = canokey_ctap::status::Status::CborUnexpectedType as u8,
    InvalidCbor = canokey_ctap::status::Status::InvalidCbor as u8,
    MissingParameter = canokey_ctap::status::Status::MissingParameter as u8,
    InvalidSubcommand = canokey_ctap::status::Status::InvalidSubcommand as u8,
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
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
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
        let code = self.command.take();
        if let Some(command) = adapter::parameterless(code, self.extra)? {
            return Ok(command);
        }
        match code {
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

type Key = canokey_ctap::request::stream::Key<Status>;
pub(super) use canokey_ctap::request::stream::is_cbor_container;
pub(super) fn skip_cbor_event(
    depth: &mut u8,
    event: &canokey_protocol::cbor::Event<'_>,
) -> Result<bool, Status> {
    canokey_ctap::request::stream::skip_cbor_event::<Status>(depth, event)
}
pub(super) fn consume_cbor_body(
    event: &canokey_protocol::cbor::Event<'_>,
    body: &mut Option<(i8, usize)>,
    target: &mut [u8],
) -> Result<(), Status> {
    canokey_ctap::request::stream::consume_cbor_body::<Status>(event, body, target)
}
impl canokey_ctap::request::Error for Status {
    const INVALID_CBOR: Self = Self::InvalidCbor;
    const UNEXPECTED_TYPE: Self = Self::UnexpectedType;
    const INVALID_LENGTH: Self = Self::InvalidLength;
    const INVALID_PARAMETER: Self = Self::InvalidParameter;
    const MISSING_PARAMETER: Self = Self::MissingParameter;
    const LIMIT_EXCEEDED: Self = Self::LimitExceeded;
    const UNSUPPORTED_ALGORITHM: Self = Self::UnsupportedAlgorithm;
    const PIN_AUTH_INVALID: Self = Self::PinAuthInvalid;
    const UNSUPPORTED_OPTION: Self = Self::UnsupportedOption;
    const INVALID_OPTION: Self = Self::InvalidOption;
    const INTERNAL: Self = Self::Other;
}
