// SPDX-License-Identifier: Apache-2.0
//! Authenticated durable upload, never generic request staging in Flash.
use super::{Command, Key, Session, Status, crypto::equal, pin};
use crate::{
    ports::{DigestOperation, HashState, Platform, Record, StorageError},
    runtime::workspace::Workspace,
};
use canokey_ports::{Crypto as _, Device as _, Storage as _};
use canokey_protocol::cbor::{Encoder, Event};
use core::num::{NonZeroU8, NonZeroU16};

pub(super) const LIMIT: u16 = 4096;
const FRAGMENT: usize = super::MAX_REQUEST - 64;
// Parsed offsets fit u16 and fragments fit FRAGMENT, even before LIMIT checks.
const _: () = assert!(FRAGMENT <= usize::MAX - u16::MAX as usize);
// Canonical empty serialized array plus its SHA-256 prefix.
const EMPTY: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];
#[repr(C)]
pub struct Parameters {
    operation: Operation,
    offset: u16,
    total: Option<NonZeroU16>,
    protocol: u8,
    auth_len: Option<NonZeroU8>,
    bytes: [u8; FRAGMENT],
    auth: [u8; 32],
}
enum Operation {
    Get(u16),
    Set(u16),
}
impl Parameters {
    const fn new() -> Self {
        Self {
            operation: Operation::Get(0),
            offset: 0,
            total: None,
            protocol: 0,
            auth_len: None,
            bytes: [0; FRAGMENT],
            auth: [0; 32],
        }
    }
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
}
struct Fields {
    params: Parameters,
    get_seen: bool,
    set_seen: bool,
    offset_seen: bool,
    length_seen: bool,
    started: bool,
    previous: Option<Key>,
    key: Option<Option<i8>>,
    skip: u8,
    body: Option<(i8, usize)>,
}
impl Parser {
    pub const fn new() -> Self {
        Self {
            decoder: super::request_decoder::RequestDecoder::large_blob(),
            fields: Fields {
                params: Parameters::new(),
                get_seen: false,
                set_seen: false,
                offset_seen: false,
                length_seen: false,
                started: false,
                previous: None,
                key: None,
                skip: 0,
                body: None,
            },
        }
    }
    // Share this parser across HID and APDU callers on size-constrained targets.
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        let fields = &mut self.fields;
        self.decoder
            .consume(bytes, &mut |event, _| fields.event(event));
    }
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        memory.wipe(&mut self.fields.params.bytes);
        memory.wipe(&mut self.fields.params.auth);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let p = &mut self.fields;
        if !p.offset_seen || p.get_seen == p.set_seen {
            return Err(Status::InvalidParameter);
        }
        if p.get_seen {
            if p.length_seen || p.params.auth_len.is_some() || p.params.protocol != 0 {
                return Err(Status::InvalidParameter);
            }
        } else {
            if p.params.offset == 0 {
                // The decoder rejects lengths above LIMIT before storing them.
                if !p
                    .params
                    .total
                    .is_some_and(|n| usize::from(n.get()) >= EMPTY.len())
                {
                    return Err(Status::InvalidParameter);
                }
            } else if p.length_seen {
                return Err(Status::InvalidParameter);
            }
            if let Some(length) = p.params.auth_len {
                if p.params.protocol != 0
                    && usize::from(length.get())
                        != super::wire::pin_protocol::auth_bytes(p.params.protocol)
                {
                    return Err(Status::InvalidParameter);
                }
            }
        }
        // The validated offset belongs to the command moved out below.
        p.offset_seen = false;
        Ok(Command::LargeBlob(core::mem::replace(
            &mut p.params,
            Parameters::new(),
        )))
    }
}
impl Fields {
    fn event(&mut self, event: &Event<'_>) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if super::skip_cbor_event(&mut self.skip, event)? {
            return Ok(());
        }
        if let Some((key, _)) = self.body {
            let target: &mut [u8] = if key == 2 {
                &mut self.params.bytes
            } else {
                &mut self.params.auth
            };
            super::consume_cbor_body(event, &mut self.body, target)?;
            return Ok(());
        }
        let Some(key) = self.key.take() else {
            if matches!(event, Event::End) {
                return Ok(());
            }
            let key = Key::ordered(event, &mut self.previous)?;
            self.key = Some(key);
            return Ok(());
        };
        match key {
            Some(key @ (1 | 3 | 4 | 6)) => {
                let Event::Unsigned(n) = *event else {
                    return Err(Status::UnexpectedType);
                };
                if key == 1 && n > FRAGMENT as u64 {
                    return Err(Status::InvalidLength);
                }
                if key == 4 && n > u64::from(LIMIT) {
                    return Err(Status::LargeBlobFull);
                }
                let n = u16::try_from(n).map_err(|_| Status::InvalidParameter)?;
                match key {
                    1 => {
                        self.get_seen = true;
                        self.params.operation = Operation::Get(n);
                    }
                    3 => {
                        self.offset_seen = true;
                        self.params.offset = n;
                    }
                    4 => {
                        self.length_seen = true;
                        self.params.total = NonZeroU16::new(n);
                    }
                    _ => {
                        if n != 1 && n != 2 {
                            return Err(Status::InvalidParameter);
                        }
                        self.params.protocol = n as u8;
                    }
                }
            }
            Some(key @ (2 | 5)) => {
                let Event::Bytes(n) = *event else {
                    return Err(Status::UnexpectedType);
                };
                if key == 2 {
                    if usize::from(n) > FRAGMENT {
                        return Err(Status::InvalidLength);
                    }
                    self.set_seen = true;
                    self.params.operation = Operation::Set(n);
                } else {
                    if n != super::wire::pin_protocol::AUTH_V1_BYTES as u16
                        && n != super::wire::pin_protocol::AUTH_V2_BYTES as u16
                    {
                        return Err(Status::InvalidParameter);
                    }
                    self.params.auth_len = NonZeroU8::new(n as u8);
                }
                self.body = Some((key, 0));
            }
            _ => {
                if matches!(
                    event,
                    Event::Map(_) | Event::Array(_) | Event::Text(_) | Event::Bytes(_)
                ) {
                    self.skip = 1;
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Upload {
    active: bool,
    length: u16,
    next: u16,
    checksum: [u8; 16],
    hash: HashState,
}
impl Upload {
    pub const fn new() -> Self {
        Self {
            active: false,
            length: 0,
            next: 0,
            checksum: [0; 16],
            hash: HashState {
                bytes: [0; crate::ports::HASH_STATE_BYTES],
            },
        }
    }
}
impl Session {
    pub(super) fn abort_blob(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        if self.upload.active {
            let _ = p
                .crypto
                .digest(DigestOperation::Abort, &mut self.upload.hash, &[], &mut []);
            p.storage.stage_abort();
            self.upload.active = false;
        }
    }
    #[inline(never)]
    pub(super) fn large_blob(
        &mut self,
        params: &mut Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let result = self.large_blob_inner(params, w, p);
        // Offset validation precedes authentication and staging. Reject the
        // fragment without discarding the accepted prefix, so the client can
        // retry at the expected offset. Other errors still abort the upload.
        if result.is_err() && !matches!(result, Err(Status::InvalidSequence)) {
            self.abort_blob(p);
        }
        result
    }
    fn large_blob_inner(
        &mut self,
        params: &mut Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let offset = usize::from(params.offset);
        let n = match params.operation {
            Operation::Get(count) => {
                let size = match p.storage.size(Record::CtapLargeBlob) {
                    Ok(n) => Some(n as usize),
                    Err(StorageError::Missing) => None,
                    _ => return Err(Status::Other),
                };
                let total = size.unwrap_or(EMPTY.len());
                if total > usize::from(LIMIT) || offset > total {
                    return Err(Status::InvalidParameter);
                }
                let n = usize::from(count).min(total - offset);
                processing(p);
                w.output[0] = 0;
                let mut e = Encoder::new(&mut w.output[1..]);
                e.map(1)
                    .u8(1)
                    .bytes_len(n as u64)
                    .finish()
                    .map_err(|_| Status::Other)?;
                let prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
                if size.is_some() {
                    self.auth_response = Some(super::Response::Blob {
                        offset: offset as u32,
                        length: n,
                        prefix,
                    });
                } else {
                    w.output[prefix..prefix + n].copy_from_slice(&EMPTY[offset..offset + n]);
                }
                return Ok(prefix + n);
            }
            Operation::Set(fragment_len) => usize::from(fragment_len),
        };
        if offset != 0 && (!self.upload.active || offset != usize::from(self.upload.next)) {
            return Err(Status::InvalidSequence);
        }
        let policy = pin::policy(p)?;
        let required = policy.pin_length != 0 || policy.flags & pin::ALWAYS_UV != 0;
        if required {
            let auth_len = params.auth_len.ok_or(Status::PuatRequired)?.get();
            if params.protocol == 0 {
                return Err(Status::MissingParameter);
            }
            // CTAP largeBlobs proof: 32*FF || 0C00 || offset(uint32LE) || SHA256(fragment).
            const COMMAND_AT: usize = 32;
            const OFFSET_AT: usize = COMMAND_AT + 2;
            const HASH_AT: usize = OFFSET_AT + 4;
            let mut message = [0xff; HASH_AT + 32];
            message[COMMAND_AT..OFFSET_AT].copy_from_slice(&[super::LARGE_BLOBS, 0x00]);
            message[OFFSET_AT..HASH_AT].copy_from_slice(&(offset as u32).to_le_bytes());
            p.crypto
                .sha256(
                    &params.bytes[..n],
                    // HASH_AT leaves exactly the SHA-256 output width.
                    (&mut message[HASH_AT..]).try_into().unwrap(),
                )
                .map_err(|_| Status::Other)?;
            self.authorize(
                params.protocol,
                &params.auth[..usize::from(auth_len)],
                &message,
                pin::PERMISSION_LARGE_BLOB_WRITE,
                None,
                p,
            )?;
        }
        if let Some(length) = params.total {
            self.abort_blob(p);
            self.upload.length = length.get();
            self.upload.next = 0;
            self.upload.checksum.fill(0);
            p.storage.stage_begin().map_err(|_| Status::Other)?;
            self.upload.active = true;
            p.crypto
                .digest(DigestOperation::Init, &mut self.upload.hash, &[], &mut [])
                .map_err(|_| Status::Other)?;
        }
        // The parser and the static bound above prove this sum cannot wrap.
        let end = offset.wrapping_add(n);
        if end > usize::from(self.upload.length) {
            return Err(Status::InvalidParameter);
        }
        processing(p);
        // An active upload retains a parsed length in 17..=LIMIT.
        let data_end = usize::from(self.upload.length.wrapping_sub(16));
        let hashed = n.min(data_end.saturating_sub(offset));
        p.crypto
            .digest(
                DigestOperation::Update,
                &mut self.upload.hash,
                &params.bytes[..hashed],
                &mut [],
            )
            .map_err(|_| Status::Other)?;
        if hashed < n {
            // A fragment crossing data_end starts the checksum at zero;
            // fragments already in the checksum retain their relative offset.
            let start = offset.saturating_sub(data_end);
            let tail = &params.bytes[hashed..n];
            self.upload.checksum[start..][..tail.len()].copy_from_slice(tail);
        }
        // This is the requested durable blob, written only after authentication.
        p.storage
            .stage_append(&params.bytes[..n])
            .map_err(|_| Status::Other)?;
        // Offset equals the old cursor (or zero); end was bounded by length.
        self.upload.next = end as u16;
        if self.upload.next == self.upload.length {
            let mut digest = [0; 32];
            p.crypto
                .digest(
                    DigestOperation::Final,
                    &mut self.upload.hash,
                    &[],
                    &mut digest,
                )
                .map_err(|_| Status::Other)?;
            if !equal(&digest[..16], &self.upload.checksum) {
                return Err(Status::IntegrityFailure);
            }
            p.storage
                .stage_commit(Record::CtapLargeBlob)
                .map_err(|_| Status::Other)?;
            self.upload.active = false;
        }
        w.output[0] = 0;
        Ok(1)
    }
}

fn processing(p: &mut Platform<'_, impl crate::ports::Backends>) {
    if !p.device.contactless() {
        p.device.keepalive(false);
        // Match C's best-effort KEEPALIVE point after validation. The transport
        // observes lifecycle cancellation; this callback cannot borrow Core.
        let _ = p.device.progress();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::applets::ctap::resident::tests::Records;
    use crate::runtime::workspace::SessionWorkspace;

    #[test]
    fn invalid_operation_or_length_preserves_status() {
        let cases: &[(&[u8], Status)] = &[
            (b"\xa3\x01\x01\x02\x41x\x03\x00", Status::InvalidParameter),
            (b"\xa1\x03\x00", Status::InvalidParameter),
            (b"\xa2\x02\x41x\x03\x00", Status::InvalidParameter),
            (b"\xa3\x02\x41x\x03\x00\x04\x10", Status::InvalidParameter),
            (
                b"\xa3\x02\x41x\x03\x00\x04\x19\x10\x01",
                Status::LargeBlobFull,
            ),
        ];
        for &(body, status) in cases {
            let mut parser = Parser::new();
            parser.consume(body);
            assert_eq!(parser.finish().err(), Some(status), "{body:02x?}");
        }
    }

    #[test]
    fn out_of_order_fragment_preserves_staged_prefix() {
        let mut parser = Parser::new();
        parser.consume(b"\xa2\x02\x41x\x03\x04");
        let Ok(Command::LargeBlob(mut params)) = parser.finish() else {
            panic!("valid noninitial Set fragment");
        };
        assert_eq!(parser.finish().err(), Some(Status::InvalidParameter));
        let mut storage = Records::default();
        storage.stage_begin().unwrap();
        storage.stage_append(b"abc").unwrap();
        let mut session = Session::new();
        session.upload.active = true;
        session.upload.length = 17;
        session.upload.next = 3;
        let memory = canokey_ports::default_memory();
        let mut backing = SessionWorkspace::new();
        let mut workspace = backing.classic_with(&memory);
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut Records::default(),
            device: &mut Records::default(),
            memory: &memory,
        };
        assert_eq!(
            session.large_blob(&mut params, &mut workspace, &mut p),
            Err(Status::InvalidSequence)
        );
        assert!(session.upload.active);
        assert_eq!(session.upload.next, 3);
        assert_eq!(storage.stage, b"abc");
    }
}
