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
use canokey_protocol::cbor::{Encoder, SliceDecoder};

const PUBLIC_KEY_OFFSET: usize = crate::ports::key_layout::P;
const CREDENTIAL_MANAGEMENT_PERMISSION: u8 = 4;
const LARGE_BLOB_KEY_OFFSET: usize = 320;
const LARGE_BLOB_KEY_END: usize = LARGE_BLOB_KEY_OFFSET + 32;

fn mldsa_public_response(
    entry: &resident::Entry<'_>,
    id: &credential::Id,
    total: u8,
    subcommand: u8,
    blob_key: Option<&[u8; 32]>,
    output: &mut [u8; crate::runtime::workspace::OUTPUT_BYTES],
) -> Result<(super::pq::Pending, usize), Status> {
    output[0] = 0;
    let mut e = Encoder::new(&mut output[1..]);
    super::encoding::management_header(&mut e, entry, subcommand == 4, blob_key.is_some())
        .map_err(|_| Status::Other)?;
    e.u8(8).finish().map_err(|_| Status::Other)?;
    super::encoding::mldsa_public_header(&mut e).map_err(|_| Status::Other)?;
    let public_at = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    super::encoding::management_tail(
        &mut e,
        id,
        (subcommand == 4).then_some(total),
        blob_key.map(|key| &key[..]),
    )
    .map_err(|_| Status::Other)?;
    let output = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    Ok((
        super::pq::Pending {
            mode: super::pq::Mode::Public,
            prefix: public_at,
            auth: 0,
            public_at,
            signature_at: 0,
            certificate: None,
            output,
            hash_prefix: (0, 0),
            hash_suffix: (0, 0),
        },
        output,
    ))
}

pub(super) struct Cursor {
    mode: u8,
    metadata_only: bool,
    next: u8,
    rp: [u8; 32],
    visited: [u8; 13],
}
impl Cursor {
    pub const fn new() -> Self {
        Self {
            mode: 0,
            metadata_only: false,
            next: 0,
            rp: [0; 32],
            visited: [0; 13],
        }
    }
}
struct User<'a> {
    id: &'a [u8],
    name: Option<&'a str>,
    display: Option<&'a str>,
}
#[derive(Default)]
struct Fields<'a> {
    rp: Option<&'a [u8; 32]>,
    id: Option<&'a credential::Id>,
    user: Option<User<'a>>,
    metadata_only: bool,
}
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
            0x80 => fields.metadata_only = d.bool().map_err(|_| Status::UnexpectedType)?,
            _ => d.skip().map_err(|_| Status::InvalidCbor)?,
        }
    }
    Ok(fields)
}
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
    p: &mut Platform<'_>,
) -> Result<u8, Status> {
    let mut count = 0;
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some(n) = resident::load(index, buffer, p)? {
            if rp.is_none_or(|rp| {
                resident::Entry::decode(&buffer[..n]).is_ok_and(|entry| entry.rp_hash == rp)
            }) {
                count += 1;
            }
        }
    }
    Ok(count)
}
fn next_rp(
    cursor: &mut Cursor,
    buffer: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<(u8, usize)>, Status> {
    for index in 0..Record::CTAP_CREDENTIALS {
        if cursor.visited[usize::from(index / 8)] & (1 << (index % 8)) != 0 {
            continue;
        }
        let Some(n) = resident::load(index, buffer, p)? else {
            continue;
        };
        let entry = resident::Entry::decode(&buffer[..n])?;
        let hash = *entry.rp_hash;
        // Group records using the one shared buffer. Scanning can overwrite
        // the selected entry, so reload it before returning its length.
        cursor.visited[usize::from(index / 8)] |= 1 << (index % 8);
        for candidate in (index + 1)..Record::CTAP_CREDENTIALS {
            if cursor.visited[usize::from(candidate / 8)] & (1 << (candidate % 8)) != 0 {
                continue;
            }
            if let Some(n) = resident::load(candidate, buffer, p)? {
                if resident::Entry::decode(&buffer[..n])?.rp_hash == &hash {
                    cursor.visited[usize::from(candidate / 8)] |= 1 << (candidate % 8);
                }
            }
        }
        let n = resident::load(index, buffer, p)?.ok_or(Status::Other)?;
        return Ok(Some((index, n)));
    }
    Ok(None)
}
impl Session {
    #[inline(never)]
    pub(super) fn manage(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let result = self.manage_inner(params, w, p);
        p.memory.wipe(&mut w.key.bytes);
        // A pending PQ response owns its seed in input until Stream::transfer
        // copies it and wipes the old workspace. Never zero it before that handoff.
        if !matches!(self.auth_response, Some(super::Response::Pending(_))) {
            p.memory.wipe(&mut w.input);
        }
        if result.is_err() {
            self.management = Cursor::new();
            p.memory.wipe(&mut w.output);
        }
        result
    }
    fn manage_inner(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let fields = parse(&params.message[PREFIX..params.len])?;
        let subcommand = params.subcommand;
        if !matches!(subcommand, 1..=7) {
            return Err(Status::InvalidSubcommand);
        }
        let continued = subcommand == 3 || subcommand == 5;
        if continued {
            if self.management.mode != subcommand {
                return Err(Status::NotAllowed);
            }
        } else {
            self.management = Cursor::new();
            if params.protocol == 0 || params.auth_len == 0 {
                return Err(Status::MissingParameter);
            }
            if matches!(subcommand, 1 | 2) && self.rp_bound {
                return Err(Status::PinAuthInvalid);
            }
            // Mutations authenticate against the stored credential's RP below.
            if !matches!(subcommand, 6 | 7) {
                self.authorize(
                    params.protocol,
                    &params.auth[..params.auth_len],
                    &params.message[PREFIX - 1..params.len],
                    CREDENTIAL_MANAGEMENT_PERMISSION,
                    fields.rp,
                    p,
                )?;
            }
        }
        w.output[0] = 0;
        if subcommand == 1 {
            let count = credential_count(None, &mut w.input, p)?;
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
        if subcommand == 2 || subcommand == 3 {
            let mut total = 0;
            if subcommand == 2 {
                let mut cursor = Cursor::new();
                while next_rp(&mut cursor, &mut w.input, p)?.is_some() {
                    total += 1;
                }
            }
            let (_, n) = next_rp(&mut self.management, &mut w.input, p)?.ok_or(if continued {
                Status::NotAllowed
            } else {
                Status::NoCredentials
            })?;
            self.management.mode = 3;
            let entry = resident::Entry::decode(&w.input[..n])?;
            let mut e = Encoder::new(&mut w.output[1..]);
            let result = (|| {
                e.map(if subcommand == 2 { 3 } else { 2 })
                    .u8(3)
                    .map(1)
                    .str("id")
                    .str(entry.rp);
                e.u8(4).bytes(entry.rp_hash);
                if subcommand == 2 {
                    e.u8(5).u8(total);
                }
                e.finish()
            })();
            result.map_err(|_| Status::Other)?;
            return Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len());
        }
        if subcommand == 4 || subcommand == 5 {
            if subcommand == 4 {
                self.management.rp = *fields.rp.ok_or(Status::MissingParameter)?;
                self.management.metadata_only = fields.metadata_only;
            }
            let total = if subcommand == 4 {
                credential_count(Some(&self.management.rp), &mut w.input, p)?
            } else {
                0
            };
            for index in self.management.next..Record::CTAP_CREDENTIALS {
                if let Some(n) = resident::load(index, &mut w.input, p)? {
                    let entry = resident::Entry::decode(&w.input[..n])?;
                    if *entry.rp_hash != self.management.rp {
                        continue;
                    }
                    self.management.next = index + 1;
                    self.management.mode = 5;
                    let id = *entry.id;
                    let algorithm = credential::open(&id, self.sm2, &self.management.rp, w, p)?;
                    if algorithm == crate::ports::alg::MLDSA65 && !self.management.metadata_only {
                        let entry = resident::Entry::decode(&w.input[..n])?;
                        let has_blob_key = id[1] & resident::LARGE_BLOB_KEY != 0;
                        if has_blob_key {
                            credential::large_blob_key(
                                &id,
                                &self.management.rp,
                                (&mut w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END])
                                    .try_into()
                                    .unwrap(),
                                p,
                            )?;
                        }
                        let blob_key = has_blob_key.then(|| {
                            (&w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END])
                                .try_into()
                                .unwrap()
                        });
                        let (plan, length) = mldsa_public_response(
                            &entry,
                            &id,
                            total,
                            subcommand,
                            blob_key,
                            &mut w.output,
                        )?;
                        // Encode directly from the input record before reusing
                        // it for the stream seed; maximal user records exceed 256 B.
                        w.input[32..64].copy_from_slice(&w.key.bytes[..32]);
                        self.auth_response = Some(super::Response::Pending(plan));
                        return Ok(length + super::pq::PUBLIC_BYTES);
                    }
                    let public_len = if self.management.metadata_only {
                        0
                    } else {
                        let n = p
                            .crypto
                            .key_operation(
                                KeyOperation::Public,
                                algorithm,
                                &mut w.key,
                                &[],
                                &mut w.output,
                            )
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
                            &id,
                            &self.management.rp,
                            (&mut w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END])
                                .try_into()
                                .unwrap(),
                            p,
                        )?;
                    }
                    let entry = resident::Entry::decode(&w.input[..n])?;
                    w.output[0] = 0;
                    let mut e = Encoder::new(&mut w.output[1..]);
                    let result = (|| {
                        super::encoding::management_header(
                            &mut e,
                            &entry,
                            subcommand == 4,
                            has_blob_key,
                        )?;
                        if public_len != 0 {
                            e.u8(8);
                            super::encoding::public_key(
                                &mut e,
                                algorithm,
                                self.sm2,
                                &w.key.bytes[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + public_len],
                            )?;
                        }
                        super::encoding::management_tail(
                            &mut e,
                            &id,
                            (subcommand == 4).then_some(total),
                            has_blob_key
                                .then_some(&w.key.bytes[LARGE_BLOB_KEY_OFFSET..LARGE_BLOB_KEY_END]),
                        )?;
                        if public_len == 0 {
                            e.u8(0x80)
                                .i32(credential::cose_algorithm(algorithm, self.sm2));
                        }
                        e.finish()
                    })();
                    result.map_err(|_| Status::Other)?;
                    return Ok(crate::runtime::workspace::OUTPUT_BYTES - e.writer().len());
                }
            }
            return Err(if continued {
                Status::NotAllowed
            } else {
                Status::NoCredentials
            });
        }
        let id = fields.id.ok_or(Status::MissingParameter)?;
        for index in 0..Record::CTAP_CREDENTIALS {
            let Some(n) = resident::load(index, &mut w.input, p)? else {
                continue;
            };
            let entry = resident::Entry::decode(&w.input[..n])?;
            if entry.id != id {
                continue;
            }
            self.authorize(
                params.protocol,
                &params.auth[..params.auth_len],
                &params.message[PREFIX - 1..params.len],
                CREDENTIAL_MANAGEMENT_PERMISSION,
                Some(entry.rp_hash),
                p,
            )?;
            let record = Record::ctap_credential(index).unwrap();
            if subcommand == 6 {
                p.storage.remove(record).unwrap_or_default();
            } else {
                let user = fields.user.as_ref().ok_or(Status::MissingParameter)?;
                if user.id != entry.user {
                    return Err(Status::InvalidParameter);
                }
                // Keep the ID, RP and user handle. Rewrite only variable strings,
                // then atomically replace this record; no second metadata commit.
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
                p.storage
                    .replace(record, &w.output[..at + n])
                    .unwrap_or_default();
            }
            w.output[0] = 0;
            return Ok(1);
        }
        Err(Status::NoCredentials)
    }
}
