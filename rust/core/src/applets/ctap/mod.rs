// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP parsing, PIN session and prepared responses for HID and APDU.
#![forbid(unsafe_code)]

pub mod apdu;
mod authentication;
mod client_pin;
mod config;
mod credential;
mod credential_request;
mod crypto;
mod envelope;
mod hmac_secret;
mod large_blob;
mod management;
mod pin;
pub(crate) mod pq;
pub(crate) mod provision;
mod resident;
pub(crate) mod settings;
use crate::ports::Record;
pub mod u2f;

const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;
const SELECTION: u8 = 0x0b;
const RESET: u8 = 0x07;
const CONFIG: u8 = 0x0d;
pub const MAX_REQUEST: usize = 1024;
/// Response bytes are either immutable or in the sole session workspace.
/// Encoding happens once; transport retries only read the prepared result.
pub enum Response {
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
        storage: &mut dyn crate::ports::Storage,
    ) -> Result<(), canokey_protocol::response::StatusWord> {
        use canokey_protocol::response::StatusWord as Sw;
        if let Self::Authentication {
            prefix,
            auth,
            certificate,
            total,
        } = *self
        {
            if offset.checked_add(out.len()).is_none_or(|end| end > total) {
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
            let mut skip = offset;
            let mut written = 0;
            for (index, segment) in segments.iter().enumerate() {
                let length = if index == 3 { cert_len } else { segment.len() };
                let start = skip.min(length);
                skip -= start;
                let n = (length - start).min(out.len() - written);
                if n != 0 {
                    if index == 3 {
                        storage
                            .read_at(
                                crate::ports::Record::CtapCertificate,
                                start as u32,
                                &mut out[written..written + n],
                            )
                            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                    } else {
                        out[written..written + n].copy_from_slice(&segment[start..start + n]);
                    }
                    written += n;
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
            if offset
                .checked_add(out.len())
                .is_none_or(|end| end > prefix + length)
            {
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
        let bytes = match self {
            Self::Constant(bytes) => bytes,
            Self::Prepared(n) => &workspace.output[..*n],
            Self::Blob { .. }
            | Self::Authentication { .. }
            | Self::Pending(_)
            | Self::Stream(_) => unreachable!(),
        };
        let end = offset
            .checked_add(out.len())
            .ok_or(canokey_protocol::response::StatusWord::WRONG_LENGTH)?;
        out.copy_from_slice(
            bytes
                .get(offset..end)
                .ok_or(canokey_protocol::response::StatusWord::WRONG_LENGTH)?,
        );
        Ok(())
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
            pin_attempts: 3,
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
    pub fn reset(&mut self, memory: &dyn crate::ports::Memory) {
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
        if !matches!(command, Ok(Command::NextAssertion)) {
            self.assertion.remaining = 0;
            self.assertion.hmac.clear(p.memory);
        }
        if !matches!(command, Ok(Command::Management(_))) {
            self.management = management::Cursor::new();
        }
        if !matches!(command, Ok(Command::LargeBlob(_))) {
            self.abort_blob(p);
        }
        if matches!(
            command,
            Ok(Command::Credential(_) | Command::Management(_) | Command::GetInfo)
        ) {
            match settings::Sm2::load(p) {
                Ok(config) => self.sm2 = config,
                Err(error) => {
                    self.reset(p.memory);
                    *command = Err(error);
                }
            }
        }
        let result = match &mut *command {
            Ok(Command::Wink) => {
                p.device.wink();
                Ok(0)
            }
            Ok(Command::NextAssertion) => self.next_assertion(workspace, p),
            Ok(Command::Reset) => self.reset_data(workspace, p),
            Ok(Command::Selection) => self.selection(workspace, p),
            Ok(Command::GetInfo) => self.info(workspace, p),
            Ok(Command::GetPinRetries) => self.retries(workspace, p),
            Ok(Command::Credential(params)) => {
                params.algorithm =
                    params.algorithms[..params.algorithm_count]
                        .iter()
                        .find_map(|id| match *id {
                            -7 => Some(crate::ports::alg::P256),
                            -8 => Some(crate::ports::alg::ED25519),
                            -49 => Some(crate::ports::alg::MLDSA65),
                            n if n == self.sm2.algorithm => Some(crate::ports::alg::SM2),
                            _ => None,
                        });
                self.credential(params, workspace, p)
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
                if let Ok(Command::LargeBlob(params)) = &command {
                    if let Some((offset, length, prefix)) = params.file_response {
                        return Response::Blob {
                            offset,
                            length,
                            prefix,
                        };
                    }
                }
                Response::Prepared(n)
            }
            Err(status) => Response::Constant(status.response()),
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
        let mut record = pin::load(p)?;
        let long = record[pin::FLAGS] & pin::LONG_RESET != 0;
        p.memory.wipe(&mut record);
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
        for index in 0..crate::ports::Record::CTAP_CREDENTIALS {
            p.storage
                .remove(crate::ports::Record::ctap_credential(index).unwrap())
                .map_err(|_| Status::Other)?;
        }
        self.pin_attempts = 3;
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
    fn info(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        let mut record = pin::load(p)?;
        let configured = record[pin::PIN_LENGTH] != 0;
        let minimum = record[pin::MIN_PIN_LENGTH];
        let flags = record[pin::FLAGS];
        p.memory.wipe(&mut record);
        w.output[0] = 0;
        let mut used = 0u8;
        for index in 0..Record::CTAP_CREDENTIALS {
            if let Some(n) = resident::load(index, &mut w.input, p)? {
                resident::Entry::decode(&w.input[..n])?;
                used = used.saturating_add(1);
            }
        }
        let mut e = canokey_protocol::cbor::Encoder::new(&mut w.output[1..]);
        let result = (|| {
            let versions = if flags & pin::ALWAYS_UV != 0 {
                ["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"].as_slice()
            } else {
                ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"].as_slice()
            };
            e.map(22)?.u8(1)?.array(versions.len() as u64)?;
            for version in versions {
                e.str(version)?;
            }
            e.u8(2)?
                .array(7)?
                .str("credBlob")?
                .str("credProtect")?
                .str("minPinLength")?
                .str("largeBlobKey")?
                .str("hmac-secret")?
                .str("hmac-secret-mc")?
                .str("thirdPartyPayment")?;
            e.u8(3)?.bytes(&provision::AAGUID)?;
            // Development profile: credential-key self attestation for the
            // compact non-PQ credential formats.
            e.u8(4)?
                .map(9)?
                .str("rk")?
                .bool(true)?
                .str("up")?
                .bool(true)?;
            e.str("alwaysUv")?.bool(flags & pin::ALWAYS_UV != 0)?;
            e.str("credMgmt")?.bool(true)?;
            e.str("authnrCfg")?.bool(true)?;
            e.str("clientPin")?.bool(configured)?;
            e.str("largeBlobs")?.bool(true)?;
            e.str("setMinPINLength")?.bool(true)?;
            e.str("makeCredUvNotRqd")?.bool(true)?;
            e.u8(5)?.u16(MAX_REQUEST as u16)?;
            e.u8(6)?.array(2)?.u8(1)?.u8(2)?;
            e.u8(7)?.u8(credential_request::MAX_LIST as u8)?;
            e.u8(8)?.u8(credential::ID_BYTES as u8)?;
            e.u8(9)?.array(1)?.str("usb")?;
            e.u8(10)?.array(4)?;
            for algorithm in [-7, -8, self.sm2.algorithm, -49] {
                e.map(2)?
                    .str("alg")?
                    .i32(algorithm)?
                    .str("type")?
                    .str("public-key")?;
            }
            e.u8(11)?.u16(large_blob::LIMIT)?;
            e.u8(12)?.bool(flags & pin::FORCE_CHANGE != 0)?;
            e.u8(13)?.u8(minimum)?;
            e.u8(14)?.u32(0)?;
            e.u8(15)?.u8(32)?;
            e.u8(16)?.u8(4)?;
            e.u8(20)?.u8(Record::CTAP_CREDENTIALS - used)?;
            e.u8(22)?.array(1)?.str("packed")?;
            e.u8(24)?.bool(flags & pin::LONG_RESET != 0)?;
            e.u8(26)?.array(2)?.str("nfc")?.str("usb")?;
            e.u8(29)?.u8(63)?;
            e.u8(31)?.array(3)?.u8(2)?.u8(3)?.u8(4)?;
            Ok::<(), canokey_protocol::cbor::EncodeError>(())
        })();
        result.map_err(|_| Status::Other)?;
        Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len())
    }
    fn key_agreement(
        &mut self,
        w: &mut crate::runtime::workspace::Workspace,
        p: &mut crate::ports::Platform<'_>,
    ) -> Result<usize, Status> {
        use crate::ports::{KeyOperation, alg};
        w.clear(p.memory);
        let result = (|| {
            if !self.agreement_ready {
                p.crypto
                    .key_operation(
                        KeyOperation::Generate,
                        alg::P256,
                        &mut w.key,
                        &[],
                        &mut w.input,
                    )
                    .map_err(|_| Status::Other)?;
                self.agreement.copy_from_slice(&w.key.bytes[..32]);
                self.agreement_ready = true;
            } else {
                w.key.bytes[..32].copy_from_slice(&self.agreement);
            }
            let n = p
                .crypto
                .key_operation(
                    KeyOperation::Public,
                    alg::P256,
                    &mut w.key,
                    &[],
                    &mut w.input,
                )
                .map_err(|_| Status::Other)?;
            if n != 64 {
                return Err(Status::Other);
            }
            w.output[0] = 0;
            let mut e = canokey_protocol::cbor::Encoder::new(&mut w.output[1..]);
            // {keyAgreement: {kty: EC2, alg: ECDH-ES+HKDF-256, crv: P-256, x, y}}
            e.map(1)
                .and_then(|e| e.u8(1))
                .and_then(|e| e.map(5))
                .and_then(|e| e.u8(1))
                .and_then(|e| e.u8(2))
                .and_then(|e| e.u8(3))
                .and_then(|e| e.i8(-25))
                .and_then(|e| e.i8(-1))
                .and_then(|e| e.u8(1))
                .and_then(|e| e.i8(-2))
                .and_then(|e| e.bytes(&w.input[..32]))
                .and_then(|e| e.i8(-3))
                .and_then(|e| e.bytes(&w.input[32..64]))
                .map_err(|_| Status::Other)?;
            Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len())
        })();
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(&mut w.input);
        if result.is_err() {
            self.reset(p.memory);
            p.memory.wipe(&mut w.output);
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
pub enum Status {
    LargeBlobFull,
    IntegrityFailure,
    InvalidSequence,
    UnsupportedAlgorithm,
    NoCredentials,
    InvalidOption,
    UnsupportedOption,
    CredentialExcluded,
    OperationDenied,
    LimitExceeded,
    PuatRequired,
    KeyStoreFull,
    NotAllowed,
    Cancelled,
    UserActionTimeout,
    Other,
    PinInvalid,
    PinBlocked,
    PinAuthInvalid,
    PinAuthBlocked,
    PinNotSet,
    PinPolicy,
    UnauthorizedPermission,
    InvalidLength,
    InvalidCommand,
    InvalidParameter,
    UnexpectedType,
    InvalidCbor,
    MissingParameter,
    InvalidSubcommand,
}
impl Status {
    fn response(self) -> &'static [u8] {
        match self {
            Self::LargeBlobFull => &[0x18],
            Self::IntegrityFailure => &[0x3d],
            Self::InvalidSequence => &[0x04],
            Self::UnsupportedAlgorithm => &[0x26],
            Self::NoCredentials => &[0x2e],
            Self::UnsupportedOption => &[0x2b],
            Self::InvalidOption => &[0x2c],
            Self::CredentialExcluded => &[0x19],
            Self::OperationDenied => &[0x27],
            Self::LimitExceeded => &[0x15],
            Self::PuatRequired => &[0x36],
            Self::KeyStoreFull => &[0x28],
            Self::NotAllowed => &[0x30],
            Self::Cancelled => &[0x2d],
            Self::UserActionTimeout => &[0x2f],
            Self::UnauthorizedPermission => &[0x40],
            Self::PinInvalid => &[0x31],
            Self::PinBlocked => &[0x32],
            Self::PinAuthInvalid => &[0x33],
            Self::PinAuthBlocked => &[0x34],
            Self::PinNotSet => &[0x35],
            Self::PinPolicy => &[0x37],
            Self::Other => &[0x7f],
            Self::InvalidCommand => &[0x01],
            Self::InvalidParameter => &[0x02],
            Self::InvalidLength => &[0x03],
            Self::UnexpectedType => &[0x11],
            Self::InvalidCbor => &[0x12],
            Self::MissingParameter => &[0x14],
            Self::InvalidSubcommand => &[0x3e],
        }
    }
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
            self.parser = match self.command {
                Some(CLIENT_PIN) => Parser::ClientPin(client_pin::Parser::new()),
                Some(n @ (0x0a | 0x41)) => Parser::Config(envelope::Parser::new(n)),
                Some(12) => Parser::LargeBlob(large_blob::Parser::new()),
                Some(CONFIG) => Parser::Config(envelope::Parser::new(CONFIG)),
                Some(n @ (1 | 2)) => Parser::Credential(credential_request::Parser::new(n == 1)),
                _ => Parser::None,
            };
        }
        match &mut self.parser {
            Parser::ClientPin(parser) => parser.consume(bytes),
            Parser::Config(parser) => parser.consume(bytes),
            Parser::LargeBlob(parser) => parser.consume(bytes),
            Parser::Credential(parser) => parser.consume(bytes),
            Parser::None => self.extra |= !bytes.is_empty(),
        }
    }
    pub(crate) fn clear(&mut self, memory: &dyn crate::ports::Memory) {
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
    pub fn finish(self) -> Result<Command, Status> {
        match self.command {
            None => Err(Status::InvalidLength),
            Some(8) if !self.extra => Ok(Command::NextAssertion),
            Some(8) => Err(Status::InvalidLength),
            Some(RESET) if !self.extra => Ok(Command::Reset),
            Some(RESET) => Err(Status::InvalidLength),
            Some(SELECTION) if !self.extra => Ok(Command::Selection),
            Some(SELECTION) => Err(Status::InvalidLength),
            Some(GET_INFO) if !self.extra => Ok(Command::GetInfo),
            Some(GET_INFO) => Err(Status::InvalidLength),
            Some(1 | 2 | CLIENT_PIN | CONFIG | 0x0a | 0x41 | 12) => match self.parser {
                Parser::ClientPin(parser) => parser.finish(),
                Parser::Config(parser) => parser.finish(),
                Parser::LargeBlob(parser) => parser.finish(),
                Parser::Credential(parser) => parser.finish(),
                Parser::None => Err(Status::InvalidCbor),
            },
            _ => Err(Status::InvalidCommand),
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

// Encoded integer ordering: positive major type, then negative argument.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    negative: bool,
    argument: u64,
}
impl Key {
    fn parse(event: canokey_protocol::cbor::Event<'_>) -> Result<Self, Status> {
        match event {
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

/// Validate one member of the COSE_Key agreement map shared by clientPIN and
/// hmac-secret. Unknown optional members are ignored by the caller.
pub(super) fn cose_key_field<F>(
    key: i8,
    event: canokey_protocol::cbor::Event<'_>,
    seen: &mut u8,
    mut bytes: F,
) -> Result<bool, Status>
where
    F: FnMut(i8, canokey_protocol::cbor::Event<'_>) -> Result<(), Status>,
{
    let (bit, expected) = match key {
        1 => (1, Some(2)),
        3 => (2, Some(-25)),
        -1 => (4, Some(1)),
        -2 => (8, None),
        -3 => (16, None),
        _ => return Ok(false),
    };
    *seen |= bit;
    if let Some(expected) = expected {
        if Key::parse(event)?.integer() != Some(expected) {
            return Err(Status::InvalidParameter);
        }
    } else {
        bytes(key, event)?;
    }
    Ok(true)
}

#[inline]
pub(super) fn is_cbor_container(event: canokey_protocol::cbor::Event<'_>) -> bool {
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
pub(super) fn skip_cbor_event(depth: &mut u8, event: canokey_protocol::cbor::Event<'_>) -> bool {
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
    event: canokey_protocol::cbor::Event<'_>,
    body: &mut Option<(i8, usize)>,
    target: &mut [u8],
) -> Result<(), Status> {
    let Some((key, offset)) = *body else {
        return Err(Status::Other);
    };
    match event {
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
