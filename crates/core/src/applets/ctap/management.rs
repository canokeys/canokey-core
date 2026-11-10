// SPDX-License-Identifier: Apache-2.0
//! Credential management shares the authenticated envelope and resident codec.
use super::{
    Session, Status, credential,
    envelope::{PREFIX, Parameters},
    resident,
};
use crate::{
    ports::{KeyOperation, Platform, Record},
    runtime::workspace::Workspace,
};
use canokey_ctap::resident::{rp, scan};
use canokey_ports::{Crypto as _, Memory as _};
use canokey_protocol::cbor::Encoder;
#[cfg(test)]
use canokey_protocol::cbor::SliceDecoder;
mod parser;
pub(super) use parser::{Parsed, Parser};

const PUBLIC_KEY_OFFSET: usize = crate::ports::key_layout::P;
use super::wire::management as cm;
const CREDENTIAL_MANAGEMENT_PERMISSION: u8 = super::wire::pin_protocol::PERMISSION_CREDENTIALS;
const VISITED_BYTES: usize = rp::bitmap_bytes(Record::CTAP_CREDENTIALS);
const LARGE_BLOB_KEY_OFFSET: usize = 320;
const LARGE_BLOB_KEY_END: usize = LARGE_BLOB_KEY_OFFSET + 32;

pub(super) struct Cursor {
    mode: u8,
    metadata_only: bool,
    next: u8,
    rp: [u8; 32],
    representatives: [u8; VISITED_BYTES],
}
impl Cursor {
    pub const fn new() -> Self {
        Self {
            mode: 0,
            metadata_only: false,
            next: 0,
            rp: [0; 32],
            representatives: [0; VISITED_BYTES],
        }
    }
}
pub(super) use canokey_ctap::management::Fields;
#[cfg(test)]
use canokey_ctap::management::User;
#[cfg(test)]
fn parse(bytes: &[u8]) -> Result<Fields<'_>, Status> {
    let mut fields = Fields::default();
    if bytes.is_empty() {
        return Ok(fields);
    }
    let mut d = SliceDecoder::new(bytes);
    let mut previous = None;
    for _ in 0..d
        .map()
        .map_err(|_| Status::UnexpectedType)?
        .ok_or(Status::InvalidCbor)?
    {
        let key = d.u64().map_err(|_| Status::UnexpectedType)?;
        if previous.is_some_and(|old| key <= old) {
            return Err(Status::InvalidCbor);
        }
        previous = Some(key);
        match key {
            1 => {
                fields.rp = Some(
                    d.bytes()
                        .map_err(|_| Status::UnexpectedType)?
                        .try_into()
                        .map_err(|_| Status::InvalidLength)?,
                )
            }
            2 => {
                let mut kind = false;
                let mut previous = None;
                for _ in 0..d
                    .map()
                    .map_err(|_| Status::UnexpectedType)?
                    .ok_or(Status::InvalidCbor)?
                {
                    let key = text_key(&mut d, &mut previous)?;
                    match key {
                        "id" => {
                            fields.id = Some(
                                d.bytes()
                                    .map_err(|_| Status::UnexpectedType)?
                                    .try_into()
                                    .map_err(|_| Status::NoCredentials)?,
                            )
                        }
                        "type" => {
                            kind = d.str().map_err(|_| Status::UnexpectedType)? == "public-key"
                        }
                        _ => d.skip().map_err(|_| Status::InvalidCbor)?,
                    }
                }
                if !kind || fields.id.is_none() {
                    return Err(Status::MissingParameter);
                }
            }
            3 => {
                let mut id = None;
                let mut name = None;
                let mut display = None;
                let mut previous = None;
                for _ in 0..d
                    .map()
                    .map_err(|_| Status::UnexpectedType)?
                    .ok_or(Status::InvalidCbor)?
                {
                    let key = text_key(&mut d, &mut previous)?;
                    match key {
                        "id" => {
                            let bytes = d.bytes().map_err(|_| Status::UnexpectedType)?;
                            if bytes.is_empty() || bytes.len() > 64 {
                                return Err(Status::InvalidLength);
                            }
                            id = Some(bytes);
                        }
                        "name" => name = Some(d.str().map_err(|_| Status::UnexpectedType)?),
                        "displayName" => {
                            display = Some(d.str().map_err(|_| Status::UnexpectedType)?)
                        }
                        _ => d.skip().map_err(|_| Status::InvalidCbor)?,
                    }
                }
                fields.user = Some(User {
                    id: id.ok_or(Status::MissingParameter)?,
                    name,
                    display,
                });
            }
            key if key == u64::from(cm::VENDOR_METADATA_ONLY) => {
                fields.metadata_only = d.bool().map_err(|_| Status::UnexpectedType)?
            }
            _ => d.skip().map_err(|_| Status::InvalidCbor)?,
        }
    }
    Ok(fields)
}
#[cfg(test)]
fn text_key<'a>(
    d: &mut SliceDecoder<'a>,
    previous: &mut Option<&'a str>,
) -> Result<&'a str, Status> {
    let key = d.str().map_err(|_| Status::UnexpectedType)?;
    if previous.is_some_and(|old| (key.len(), key) <= (old.len(), old)) {
        return Err(Status::InvalidCbor);
    }
    *previous = Some(key);
    Ok(key)
}
fn credential_count(
    rp: Option<&[u8; 32]>,
    buffer: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<u8, Status> {
    let mut scan = resident::Scan::new();
    canokey_ctap::resident::scan::count(Record::CTAP_CREDENTIALS, |index| {
        Ok(scan.load(index, buffer, p)?.is_some_and(|length| {
            rp.is_none_or(|rp| {
                resident::decode(&buffer[..length]).is_ok_and(|entry| entry.rp_hash == rp)
            })
        }))
    })
}
// The read-only group cache belongs to one synchronous collection pass. It is
// reset before each batch and dropped before key derivation or response work.
struct RpReader<'a, 'p, B: crate::ports::Backends> {
    scan: resident::Scan,
    buffer: &'a mut [u8],
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> rp::Reader for RpReader<'_, '_, B> {
    type Error = Status;
    fn begin_pass(&mut self) {
        self.scan = resident::Scan::new();
    }
    fn read(&mut self, index: u8) -> Result<Option<&[u8; resident::RP_HASH_BYTES]>, Status> {
        Ok(self
            .scan
            .read(index, self.buffer, self.platform)?
            .map(|(_, entry)| entry.rp_hash))
    }
}
/// Hash batches borrow the existing key workspace only during RP_BEGIN.
#[inline(never)]
fn collect_rps(
    cursor: &mut Cursor,
    buffer: &mut [u8],
    hashes: &mut [u8; crate::ports::key_layout::SIZE],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<u8, Status> {
    let (hashes, _) = hashes.as_chunks_mut::<{ resident::RP_HASH_BYTES }>();
    let mut visited = [0x00; VISITED_BYTES];
    rp::collect(
        Record::CTAP_CREDENTIALS,
        &mut visited,
        &mut cursor.representatives,
        hashes,
        &mut RpReader {
            scan: resident::Scan::new(),
            buffer,
            platform: p,
        },
    )
}
fn next_rp(
    cursor: &mut Cursor,
    buffer: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<(u8, usize)>, Status> {
    rp::next_representative(
        Record::CTAP_CREDENTIALS,
        &cursor.representatives,
        &mut cursor.next,
        |index| resident::load(index, buffer, p)?.ok_or(Status::Other),
    )
}
impl Session {
    #[inline(never)]
    pub(super) fn manage(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let result = self.manage_inner(params, w, p);
        p.memory.wipe(&mut w.key.bytes);
        // A pending PQ response owns its seed in input until Stream::transfer
        // copies it and wipes the old workspace. Never zero it before that handoff.
        if !matches!(self.auth_response, Some(super::Response::Pending(_))) {
            p.memory.wipe(w.input);
        }
        if result.is_err() {
            self.management = Cursor::new();
            p.memory.wipe(w.output);
        }
        result
    }
    #[inline(never)]
    fn manage_inner(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let fields = params.management.fields(&params.message)?;
        let request = canokey_ctap::management::Request::new(
            params.subcommand,
            params.auth_len != 0,
            params.protocol != 0,
            &fields,
        );
        canokey_ctap::management::execute(
            request,
            &mut Operation {
                session: self,
                params,
                fields,
                w,
                p,
            },
        )
    }
}
struct Operation<'a, 'r, 'w, 'p, B: crate::ports::Backends> {
    session: &'a mut Session,
    params: &'r Parameters,
    fields: Fields<'r>,
    w: &'a mut Workspace<'w>,
    p: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> canokey_ctap::management::Backend for Operation<'_, '_, '_, '_, B> {
    type Error = Status;
    type Output = usize;
    type Authenticated = canokey_ctap::client_pin::token::VerifiedRequest;
    fn reset_cursor(&mut self) {
        self.session.management = Cursor::new();
    }
    fn cursor_mode(&self) -> u8 {
        self.session.management.mode
    }
    fn continue_live(&mut self) -> Result<(), Status> {
        Ok(())
    }
    fn authorize(&mut self, deferred_rp: bool) -> Result<Self::Authenticated, Status> {
        self.session.authorize_scoped(
            self.params.protocol,
            &self.params.auth[..self.params.auth_len],
            &self.params.message[self.params.start + PREFIX - 1..self.params.len],
            CREDENTIAL_MANAGEMENT_PERMISSION,
            if self.params.subcommand == cm::CREDENTIAL_BEGIN {
                self.fields.rp
            } else {
                None
            },
            if deferred_rp {
                super::pin::AuthorizationScope::DeferredRp
            } else {
                super::pin::AuthorizationScope::Global
            },
            self.p,
        )
    }
    fn metadata(&mut self) -> Result<usize, Status> {
        let w = &mut *self.w;
        let p = &mut *self.p;
        w.output[0] = 0;
        let count = credential_count(None, w.input, p)?;
        let mut e = Encoder::new(&mut w.output[1..]);
        e.map(2)
            .u8(1)
            .u8(count)
            .u8(2)
            .u8(Record::CTAP_CREDENTIALS - count)
            .finish()
            .map_err(|_| Status::Other)?;
        return Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len());
    }
    fn rps(&mut self, first: bool) -> Result<usize, Status> {
        let w = &mut *self.w;
        let p = &mut *self.p;
        w.output[0] = 0x00;

        let mut total = 0;
        if first {
            total = collect_rps(&mut self.session.management, w.input, &mut w.key.bytes, p)?;
        }
        let (_, n) = next_rp(&mut self.session.management, w.input, p)?
            .ok_or(canokey_ctap::management::exhausted::<Status>(first))?;
        self.session.management.mode = cm::RP_NEXT;
        let entry = resident::decode(&w.input[..n])?;
        let mut e = Encoder::new(&mut w.output[1..]);
        let result = (|| {
            e.map(if first { 3 } else { 2 })
                .u8(3)
                .map(1)
                .str("id")
                .str(entry.rp);
            e.u8(4).bytes(entry.rp_hash);
            if first {
                e.u8(5).u8(total);
            }
            e.finish()
        })();
        result.map_err(|_| Status::Other)?;
        return Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len());
    }
    fn credentials(&mut self, first: bool) -> Result<usize, Status> {
        let w = &mut *self.w;
        let p = &mut *self.p;
        let fields = &self.fields;

        if first {
            self.session.management.rp = *fields.rp.ok_or(Status::MissingParameter)?;
            self.session.management.metadata_only = fields.metadata_only;
        }
        let total = if first {
            credential_count(Some(&self.session.management.rp), w.input, p)?
        } else {
            0
        };
        let selected = scan::ascending(
            self.session.management.next,
            Record::CTAP_CREDENTIALS,
            |index| {
                let Some((_, entry)) = resident::read(index, w.input, p)? else {
                    return Ok(None);
                };
                if *entry.rp_hash != self.session.management.rp {
                    return Ok(None);
                }
                self.session.management.next = index + 1;
                self.session.management.mode = cm::CREDENTIAL_NEXT;
                // Key derivation borrows only the key buffer, so the input
                // record stays validated and borrowed through encoding.
                let id = entry.id;
                let algorithm =
                    credential::open(id, self.session.sm2, &self.session.management.rp, w.key, p)?;
                let pq_public = crate::ports::mldsa::parameters(algorithm).is_some()
                    && !self.session.management.metadata_only;
                let public_len = if self.session.management.metadata_only || pq_public {
                    0
                } else {
                    let n = p
                        .crypto
                        .key_operation(KeyOperation::Public, algorithm, &mut w.key, &[], w.output)
                        .map_err(|_| Status::Other)?;
                    if n != credential::public_length(algorithm) {
                        return Err(Status::Other);
                    }
                    w.key.bytes[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + n]
                        .copy_from_slice(&w.output[..n]);
                    n
                };
                let has_blob_key = id[1] & resident::LARGE_BLOB_KEY != 0;
                if has_blob_key {
                    credential::large_blob_key(
                        id,
                        &self.session.management.rp,
                        (&mut w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END])
                            .try_into()
                            .unwrap(),
                        p,
                    )?;
                }
                if pq_public {
                    let blob_key = has_blob_key.then(|| {
                        (&w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END])
                            .try_into()
                            .unwrap()
                    });
                    let (plan, length) = canokey_ctap::streaming::reply::public(
                        &entry,
                        algorithm,
                        id,
                        first.then_some(total),
                        blob_key,
                        w.output,
                    )
                    .map_err(|_| Status::Other)?;
                    // Encode directly from the input record before reusing
                    // it for the stream seed; maximal user records exceed 256 B.
                    w.input[32..64].copy_from_slice(&w.key.bytes[..32]);
                    self.session.auth_response = Some(super::Response::Pending(plan));
                    return Ok(Some(length + credential::public_length(algorithm)));
                }
                w.output[0] = 0;
                let mut e = Encoder::new(&mut w.output[1..]);
                let result = (|| {
                    super::encoding::management_header(&mut e, &entry, first, has_blob_key)?;
                    if public_len != 0 {
                        e.u8(8);
                        super::encoding::public_key(
                            &mut e,
                            algorithm,
                            self.session.sm2,
                            &w.key.bytes[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + public_len],
                        )?;
                    }
                    super::encoding::management_tail(
                        &mut e,
                        id,
                        first.then_some(total),
                        has_blob_key
                            .then_some(&w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END]),
                    )?;
                    if public_len == 0 {
                        e.u8(cm::VENDOR_ALGORITHM)
                            .i32(credential::cose_algorithm(algorithm, self.session.sm2));
                    }
                    e.finish()
                })();
                result.map_err(|_| Status::Other)?;
                Ok(Some(
                    crate::runtime::workspace::OUTPUT_BYTES - e.writer().len(),
                ))
            },
        )?;
        if let Some((_, length)) = selected {
            return Ok(length);
        }
        Err(canokey_ctap::management::exhausted::<Status>(first))
    }
    fn mutate(
        &mut self,
        delete: bool,
        authenticated: Self::Authenticated,
    ) -> Result<usize, Status> {
        let w = &mut *self.w;
        let p = &mut *self.p;
        let fields = &self.fields;
        let id = fields.id.ok_or(Status::MissingParameter)?;
        let selected = scan::ascending(0, Record::CTAP_CREDENTIALS, |index| {
            let Some(n) = resident::load(index, w.input, p)? else {
                return Ok(None);
            };
            let entry = resident::decode(&w.input[..n])?;
            if entry.id != id {
                return Ok(None);
            }
            self.session
                .finish_management(&authenticated, entry.rp_hash, p)?;
            if delete {
                resident::replace(
                    index,
                    &[],
                    (&mut w.key.bytes[..resident::COPY_BYTES])
                        .try_into()
                        .unwrap(),
                    p,
                )?;
            } else {
                let user = fields.user.as_ref().ok_or(Status::MissingParameter)?;
                if user.id != entry.user {
                    return Err(Status::InvalidParameter);
                }
                // Keep the ID, RP and user handle. Rewrite only variable strings,
                // then publish the group atomically; no second metadata commit.
                let name = user.name.unwrap_or(entry.name).as_bytes();
                let display = user.display.unwrap_or(entry.display).as_bytes();
                let at = credential::ID_BYTES + 32;
                w.output[..at].copy_from_slice(&w.input[..at]);
                let n = resident::encode_fields(
                    &mut w.output[at..],
                    &[
                        entry.rp.as_bytes(),
                        entry.user,
                        resident::text_prefix(&name[..name.len().min(64)]),
                        resident::text_prefix(&display[..display.len().min(64)]),
                        entry.blob,
                    ],
                );
                // An uncertain publication must not acknowledge stale user data.
                // Like deletion, failure revokes the command's continuation/token.
                resident::replace(
                    index,
                    &w.output[..at + n],
                    (&mut w.key.bytes[..resident::COPY_BYTES])
                        .try_into()
                        .unwrap(),
                    p,
                )?;
            }
            w.output[0] = 0;
            Ok(Some(1))
        })?;
        if let Some((_, length)) = selected {
            return Ok(length);
        }
        Err(Status::NoCredentials)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::resident::tests::{Records, resident};
    use super::*;

    struct Mac {
        calls: usize,
    }
    impl crate::ports::Crypto for Mac {
        fn mac(
            &mut self,
            algorithm: u8,
            _: &[u8],
            _: &[u8],
            out: &mut [u8; 64],
        ) -> Result<(), crate::ports::CryptoError> {
            assert_eq!(algorithm, 0x02);
            self.calls += 1;
            out.fill(0xa5);
            Ok(())
        }
        fn random(&mut self, _: &mut [u8]) -> Result<(), crate::ports::CryptoError> {
            panic!("management mutation must not request entropy");
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            panic!("management must use HMAC-SHA-256");
        }
    }
    struct Clock {
        expire_on_resolution: bool,
        queries: usize,
    }
    impl crate::ports::Device for Clock {
        fn now(&mut self) -> u32 {
            self.queries += 1;
            if self.expire_on_resolution && self.queries > 1 {
                30_001
            } else {
                20
            }
        }
        fn progress(&mut self) -> bool {
            true
        }
        fn serial(&mut self, _: &mut [u8; 4]) {
            unreachable!()
        }
        fn touched(&mut self) -> bool {
            false
        }
        fn led(&mut self, _: bool) {}
    }
    #[test]
    fn actual_mutation_preflight_resolves_record_rp_before_usage_or_publication() {
        use super::super::{Command, envelope};
        use std::vec;
        // Cases: bad MAC, mismatching RP, absent ID, deletion, expiry after IO. A fake
        // primitive isolates control/IO ordering; native suites cover HMAC.
        for case in 0..5 {
            let mut storage = Records::default();
            storage.records.push(resident(0, 0x07, 1));
            let mut id = storage.records[0].1[..credential::ID_BYTES].to_vec();
            if case == 2 {
                id[2] ^= 0x01;
            }
            let mut raw = vec![0xa4, 0x01, cm::DELETE, 0x02, 0xa1, 0x02, 0xa2];
            raw.extend_from_slice(b"\x62id\x58");
            raw.push(credential::ID_BYTES as u8);
            raw.extend_from_slice(&id);
            raw.extend_from_slice(b"\x64type\x6apublic-key\x03\x02\x04\x58\x20");
            raw.extend_from_slice(&[if case == 0 { 0x5a } else { 0xa5 }; 32]);
            let mut parser = envelope::Parser::new(0x0a);
            parser.consume(&raw);
            let Command::Management(parameters) = parser.finish().unwrap() else {
                panic!("management expected");
            };
            let mut crypto = Mac { calls: 0 };
            let mut device = Clock {
                expire_on_resolution: case == 4,
                queries: 0,
            };
            let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &canokey_ports::default_memory(),
            };
            let mut session = Session::new();
            session.pin.start_token(CREDENTIAL_MANAGEMENT_PERMISSION, 1);
            session.pin.mark_token_used(1);
            session
                .pin
                .bind_token_rp(Some([if case == 1 { 0x08 } else { 0x07 }; 32]));
            let mut backing = crate::runtime::workspace::SessionWorkspace::new();
            let result = session.manage(&parameters, &mut backing.classic(), &mut platform);
            assert_eq!(
                result,
                match case {
                    0 | 1 | 4 => Err(Status::PinAuthInvalid),
                    2 => Err(Status::NoCredentials),
                    _ => Ok(1),
                }
            );
            assert_eq!(
                session.pin.token().last_used(),
                match case {
                    3 => 20,
                    4 => 0,
                    _ => 1,
                }
            );
            assert_eq!(session.management.mode, 0x00);
            assert_eq!(platform.crypto.calls, 1);
            if case == 0 {
                assert_eq!(platform.storage.size_calls + platform.storage.read_calls, 0);
            }
            assert_eq!(platform.storage.mutations > 0, case == 3);
        }
    }

    #[test]
    fn rp_index_batches_full_hashes_in_slot_order_without_writes() {
        for distinct in [1, 7, 40, 41, 100] {
            let mut storage = Records::default();
            storage.records = (0..Record::CTAP_CREDENTIALS)
                .map(|i| resident(i, i % distinct, 1))
                .collect();
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut Records::default(),
                device: &mut Records::default(),
                memory: &canokey_ports::default_memory(),
            };
            let mut cursor = Cursor::new();
            let mut out = [0; resident::MAX_BYTES];
            let mut hashes = [0; crate::ports::key_layout::SIZE];
            assert_eq!(
                collect_rps(&mut cursor, &mut out, &mut hashes, &mut p),
                Ok(distinct)
            );
            // 40 hashes fit in the existing key workspace: at most three passes.
            assert!(p.storage.size_calls + p.storage.read_calls <= 270);
            for index in 0..distinct {
                let (slot, n) = next_rp(&mut cursor, &mut out, &mut p).unwrap().unwrap();
                assert_eq!(slot, index);
                assert_eq!(resident::decode(&out[..n]).unwrap().rp_hash, &[index; 32]);
            }
            assert_eq!(next_rp(&mut cursor, &mut out, &mut p).unwrap(), None);
            assert_eq!(p.storage.mutations, 0);
        }
    }

    #[test]
    fn rp_index_handles_holes_and_compares_all_hash_bytes() {
        let first = resident(3, 7, 1);
        let mut second = resident(10, 7, 1);
        // Share the first 31 bytes, but represent different RPs.
        second.1[credential::ID_BYTES + 31] ^= 1;
        let duplicate = resident(99, 7, 1);
        let mut storage = Records::default();
        storage.records = [first, second, duplicate].into();
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut Records::default(),
            device: &mut Records::default(),
            memory: &canokey_ports::default_memory(),
        };
        let mut cursor = Cursor::new();
        let mut out = [0; resident::MAX_BYTES];
        // Sparse slots include entire missing groups.
        assert_eq!(
            collect_rps(
                &mut cursor,
                &mut out,
                &mut [0; crate::ports::key_layout::SIZE],
                &mut p
            ),
            Ok(2)
        );
        assert_eq!(
            next_rp(&mut cursor, &mut out, &mut p).unwrap().unwrap().0,
            3
        );
        assert_eq!(
            next_rp(&mut cursor, &mut out, &mut p).unwrap().unwrap().0,
            10
        );
        assert_eq!(next_rp(&mut cursor, &mut out, &mut p).unwrap(), None);
        p.storage.fail = Some(crate::ports::StorageError::Unavailable);
        assert_eq!(
            collect_rps(
                &mut Cursor::new(),
                &mut out,
                &mut [0; crate::ports::key_layout::SIZE],
                &mut p
            ),
            Err(Status::Other)
        );
        assert_eq!(p.storage.mutations, 0);
    }
}
