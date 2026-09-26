// SPDX-License-Identifier: Apache-2.0
//! Authenticated durable upload, never generic request staging in Flash.
use super::{Command, Key, Session, Status, crypto::equal, pin};
use crate::{
    ports::{DigestOperation, HashState, Platform, Record, StorageError},
    runtime::workspace::Workspace,
};
use canokey_protocol::cbor::{Encoder, Event};

pub(super) const LIMIT: u16 = 4096;
const FRAGMENT: usize = super::MAX_REQUEST - 64;
// Canonical empty serialized array plus its SHA-256 prefix.
const EMPTY: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];
pub struct Parameters {
    get: Option<u16>,
    set: Option<usize>,
    offset: Option<u16>,
    length: Option<u16>,
    bytes: [u8; FRAGMENT],
    auth: [u8; 32],
    auth_len: usize,
    protocol: u8,
    pub(super) file_response: Option<(u32, usize, usize)>,
}
impl Parameters {
    const fn new() -> Self {
        Self {
            get: None,
            set: None,
            offset: None,
            length: None,
            bytes: [0; FRAGMENT],
            auth: [0; 32],
            auth_len: 0,
            protocol: 0,
            file_response: None,
        }
    }
}
pub struct Parser {
    decoder: super::request_decoder::RequestDecoder,
    fields: Fields,
}
struct Fields {
    params: Parameters,
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
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.fields.params.bytes);
        memory.wipe(&mut self.fields.params.auth);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.decoder.finish()?;
        let p = &self.fields.params;
        let offset = p.offset.ok_or(Status::InvalidParameter)?;
        if p.get.is_some() == p.set.is_some() {
            return Err(Status::InvalidParameter);
        }
        if p.get.is_some() {
            if p.length.is_some() || p.auth_len != 0 || p.protocol != 0 {
                return Err(Status::InvalidParameter);
            }
        } else {
            if offset == 0 {
                let length = p.length.ok_or(Status::InvalidParameter)?;
                if length < 17 {
                    return Err(Status::InvalidParameter);
                }
                if length > LIMIT {
                    return Err(Status::LargeBlobFull);
                }
            } else if p.length.is_some() {
                return Err(Status::InvalidParameter);
            }
            if p.auth_len != 0
                && p.protocol != 0
                && p.auth_len != if p.protocol == 1 { 16 } else { 32 }
            {
                return Err(Status::InvalidParameter);
            }
        }
        Ok(Command::LargeBlob(core::mem::replace(
            &mut self.fields.params,
            Parameters::new(),
        )))
    }
}
impl Fields {
    fn event(&mut self, event: Event<'_>) -> Result<(), Status> {
        if !self.started {
            if !matches!(event, Event::Map(_)) {
                return Err(Status::UnexpectedType);
            }
            self.started = true;
            return Ok(());
        }
        if super::skip_cbor_event(&mut self.skip, event) {
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
                let Event::Unsigned(n) = event else {
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
                        self.params.get = Some(n);
                    }
                    3 => self.params.offset = Some(n),
                    4 => self.params.length = Some(n),
                    _ => {
                        if n != 1 && n != 2 {
                            return Err(Status::InvalidParameter);
                        }
                        self.params.protocol = n as u8;
                    }
                }
            }
            Some(key @ (2 | 5)) => {
                let Event::Bytes(n) = event else {
                    return Err(Status::UnexpectedType);
                };
                if key == 2 {
                    if usize::from(n) > FRAGMENT {
                        return Err(Status::InvalidLength);
                    }
                    self.params.set = Some(usize::from(n));
                } else {
                    if n != 16 && n != 32 {
                        return Err(Status::InvalidParameter);
                    }
                    self.params.auth_len = usize::from(n);
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
    pub(super) fn abort_blob(&mut self, p: &mut Platform<'_>) {
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
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let result = self.large_blob_inner(params, w, p);
        if result.is_err() {
            self.abort_blob(p);
        }
        result
    }
    fn large_blob_inner(
        &mut self,
        params: &mut Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let offset = usize::from(params.offset.unwrap());
        if let Some(get) = params.get {
            let size = match p.storage.size(Record::CtapLargeBlob) {
                Ok(n) => Some(n as usize),
                Err(StorageError::Missing) => None,
                _ => return Err(Status::Other),
            };
            let total = size.unwrap_or(EMPTY.len());
            if total > usize::from(LIMIT) || offset > total {
                return Err(Status::InvalidParameter);
            }
            let n = usize::from(get).min(total - offset);
            w.output[0] = 0;
            let mut e = Encoder::new(&mut w.output[1..]);
            e.map(1)
                .u8(1)
                .bytes_len(n as u64)
                .finish()
                .map_err(|_| Status::Other)?;
            let prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
            if size.is_some() {
                params.file_response = Some((offset as u32, n, prefix));
            } else {
                w.output[prefix..prefix + n].copy_from_slice(&EMPTY[offset..offset + n]);
            }
            return Ok(prefix + n);
        }
        let n = params.set.unwrap();
        if offset != 0 && (!self.upload.active || offset != usize::from(self.upload.next)) {
            return Err(Status::InvalidSequence);
        }
        let mut policy = [0; pin::RECORD_BYTES];
        pin::load(p, &mut policy)?;
        let required = policy[pin::PIN_LENGTH] != 0 || policy[pin::FLAGS] & pin::ALWAYS_UV != 0;
        p.memory.wipe(&mut policy);
        if required {
            if params.auth_len == 0 {
                return Err(Status::PuatRequired);
            }
            if params.protocol == 0 {
                return Err(Status::MissingParameter);
            }
            let mut message = [0xff; 70];
            message[32..34].copy_from_slice(&[12, 0]);
            message[34..38].copy_from_slice(&(offset as u32).to_le_bytes());
            p.crypto
                .sha256(&params.bytes[..n], (&mut message[38..]).try_into().unwrap())
                .map_err(|_| Status::Other)?;
            self.authorize(
                params.protocol,
                &params.auth[..params.auth_len],
                &message,
                pin::PERMISSION_LARGE_BLOB_WRITE,
                None,
                p,
            )?;
        }
        if offset == 0 {
            self.abort_blob(p);
            self.upload.length = params.length.unwrap();
            self.upload.next = 0;
            self.upload.checksum.fill(0);
            p.storage.stage_begin().map_err(|_| Status::Other)?;
            self.upload.active = true;
            p.crypto
                .digest(DigestOperation::Init, &mut self.upload.hash, &[], &mut [])
                .map_err(|_| Status::Other)?;
        }
        if offset + n > usize::from(self.upload.length) {
            return Err(Status::InvalidParameter);
        }
        let data_end = usize::from(self.upload.length) - 16;
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
            let start = offset + hashed - data_end;
            self.upload.checksum[start..start + n - hashed]
                .copy_from_slice(&params.bytes[hashed..n]);
        }
        // This is the requested durable blob, written only after authentication.
        p.storage
            .stage_append(&params.bytes[..n])
            .map_err(|_| Status::Other)?;
        self.upload.next += n as u16;
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
