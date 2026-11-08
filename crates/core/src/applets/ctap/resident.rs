// SPDX-License-Identifier: Apache-2.0
//! Four logical credentials share one atomically published record.
use super::{
    Status,
    credential::{ID_BYTES, Id},
    credential_request::Parameters,
    crypto::equal,
};
use crate::ports::{Platform, Record, StorageError};
use canokey_ports::Storage as _;

pub(super) use canokey_ctap::resident::{
    FIXED_BYTES, MAX_BYTES, RESIDENT, RP_DISPLAY_BYTES, RP_HASH_BYTES, USER_DISPLAY_BYTES,
    USER_ID_BYTES, USER_NAME_BYTES,
};
pub(super) const LARGE_BLOB_KEY: u8 = 0x08;
#[cfg(test)]
use canokey_ctap::resident::group::FORMAT as GROUP_FORMAT;
use canokey_ctap::resident::group::{self, Replacement, member_length};
use canokey_ctap::resident::group::{HEADER_BYTES as GROUP_HEADER, MEMBERS as GROUP_MEMBERS};
const _: () = assert!(Record::CTAP_GROUP_MEMBERS as usize == GROUP_MEMBERS);
pub(super) const COPY_BYTES: usize = (GROUP_MEMBERS - 1) * MAX_BYTES;

fn group_header(
    record: Record,
    header: &mut [u8; GROUP_HEADER],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    *header = group::empty();
    let size = match p.storage.size(record) {
        Ok(n) => n,
        Err(StorageError::Missing) => return Ok(()),
        Err(_) => return Err(Status::Other),
    };
    p.storage
        .read_at(record, 0, header)
        .map_err(|_| Status::Other)?;
    group::validate(header, size as usize).map_err(|_| Status::Other)
}

/// Buffer up to three unchanged members before atomically publishing the group.
/// The caller lends unused key workspace; no member-sized stack cache is added.
pub(super) fn replace(
    index: u8,
    value: &[u8],
    copy: &mut [u8; COPY_BYTES],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    let record = Record::ctap_group(index / Record::CTAP_GROUP_MEMBERS).ok_or(Status::Other)?;
    if !value.is_empty() {
        if value.len() > MAX_BYTES {
            return Err(Status::Other);
        }
        decode(value)?;
    }
    // The key workspace is exclusively scratch until this synchronous update
    // returns. Every exit after admission wipes the complete peer reservation.
    let mut reservation = canokey_ctap::workspace::Reservation::new(copy, p.memory);
    let copy = reservation.bytes();
    let result = (|| {
        let mut header = [0; GROUP_HEADER];
        group_header(record, &mut header, p)?;
        let target = usize::from(index % Record::CTAP_GROUP_MEMBERS);
        let replacement =
            Replacement::new(&header, target, value.len()).map_err(|_| Status::Other)?;
        let before = replacement.offset - GROUP_HEADER;
        let target_offset = replacement.offset;
        let target_length = replacement.old_length;
        if target_length != 0 && target_length == value.len() {
            let bytes = &mut copy[..target_length];
            p.storage
                .read_at(record, target_offset as u32, bytes)
                .map_err(|_| Status::Other)?;
            // The replacement is already validated. Only unchanged peers need
            // decoding; the target is either identical or replaced in full.
            return if bytes == value {
                Ok(())
            } else {
                p.storage
                    .replace_at(record, target_offset as u32, value)
                    .map_err(|_| Status::Other)
            };
        }
        let mut offset = GROUP_HEADER as u32;
        let mut used = 0;
        // Read and validate before leasing the shared file cache for staging.
        // Interleaved reads would close/commit the stage once per member.
        for member in 0..GROUP_MEMBERS {
            let n = member_length(&header, member);
            if member != target && n != 0 {
                let bytes = copy.get_mut(used..used + n).ok_or(Status::Other)?;
                p.storage
                    .read_at(record, offset, bytes)
                    .map_err(|_| Status::Other)?;
                decode(bytes)?;
                used += n;
            }
            offset += n as u32;
        }
        if value.is_empty() && used == 0 {
            return p.storage.remove(record).map_err(|_| Status::Other);
        }
        Replacement::set_length(&mut header, target, value.len());
        let publication = p
            .storage
            .stage_parts(&[&header, &copy[..before], value, &copy[before..used]])
            .and_then(|()| p.storage.stage_commit(record));
        if publication.is_err() {
            p.storage.stage_abort();
        }
        publication.map_err(|_| Status::Other)
    })();
    drop(reservation);
    result
}

pub(super) use canokey_ctap::resident::{Entry, display_rp, encode_fields, text_prefix};

pub(super) fn decode(bytes: &[u8]) -> Result<Entry<'_>, Status> {
    Entry::decode(bytes).map_err(|_| Status::Other)
}

pub(super) fn load(
    index: u8,
    out: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<usize>, Status> {
    let record = Record::ctap_group(index / Record::CTAP_GROUP_MEMBERS).ok_or(Status::Other)?;
    let mut header = [0; GROUP_HEADER];
    group_header(record, &mut header, p)?;
    load_member(index, record, &header, out, p)
}
#[inline(never)]
fn load_member(
    index: u8,
    record: Record,
    header: &[u8; GROUP_HEADER],
    out: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<usize>, Status> {
    let member = usize::from(index % Record::CTAP_GROUP_MEMBERS);
    let n = member_length(header, member);
    if n == 0 {
        return Ok(None);
    }
    let offset = group::member_offset(header, member);
    p.storage
        .read_at(record, offset as u32, &mut out[..n])
        .map_err(|_| Status::Other)?;
    Ok(Some(n))
}
/// Validated group metadata for one synchronous read-only scan only.
/// Drop before mutations, crypto, progress callbacks or returning a response.
pub(super) struct Scan {
    group: u8,
    header: [u8; GROUP_HEADER],
}
impl Scan {
    pub const fn new() -> Self {
        Self {
            group: Record::CTAP_CREDENTIALS,
            header: [0; GROUP_HEADER],
        }
    }
    pub fn load(
        &mut self,
        index: u8,
        out: &mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<Option<usize>, Status> {
        let group = index / Record::CTAP_GROUP_MEMBERS;
        let record = Record::ctap_group(group).ok_or(Status::Other)?;
        if self.group != group {
            // A failed read may partially overwrite the header; never retain
            // the previous group's cache tag across that failure.
            self.group = Record::CTAP_CREDENTIALS;
            group_header(record, &mut self.header, p)?;
            self.group = group;
        }
        load_member(index, record, &self.header, out, p)
    }
    pub fn read<'a>(
        &mut self,
        index: u8,
        out: &'a mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<Option<(usize, Entry<'a>)>, Status> {
        decode_loaded(self.load(index, out, p)?, out)
    }
}
/// Load and validate one occupied resident slot without copying its fields.
#[inline(never)]
pub(super) fn read<'a>(
    index: u8,
    out: &'a mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<(usize, Entry<'a>)>, Status> {
    decode_loaded(load(index, out, p)?, out)
}
#[inline(never)]
fn decode_loaded(length: Option<usize>, out: &[u8]) -> Result<Option<(usize, Entry<'_>)>, Status> {
    let Some(n) = length else {
        return Ok(None);
    };
    Ok(Some((n, decode(&out[..n])?)))
}
pub(super) fn store(
    params: &Parameters,
    id: &Id,
    rp_hash: &[u8; RP_HASH_BYTES],
    out: &mut [u8],
    copy: &mut [u8; COPY_BYTES],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    let mut slot = None;
    let mut scan = Scan::new();
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some((_, entry)) = scan.read(index, out, p)? {
            if equal(entry.rp_hash, rp_hash) && equal(entry.user, &params.user[..params.user_len]) {
                slot = Some(index);
                break;
            }
        } else {
            slot.get_or_insert(index);
        }
    }
    let slot = slot.ok_or(Status::KeyStoreFull)?;
    out[..ID_BYTES].copy_from_slice(id);
    out[ID_BYTES..FIXED_BYTES].copy_from_slice(rp_hash);
    let at = FIXED_BYTES;
    let mut display = [0; RP_DISPLAY_BYTES];
    let n = encode_fields(
        &mut out[at..],
        &[
            display_rp(&params.rp[..params.rp_len], &mut display),
            &params.user[..params.user_len],
            &params.name[..params.name_len],
            &params.display[..params.display_len],
            &params.cred_blob[..params
                .cred_blob_len
                .filter(|&n| n <= params.cred_blob.len())
                .unwrap_or(0)],
        ],
    );
    replace(slot, &out[..at + n], copy, p)
}

pub(super) fn find(
    id: &Id,
    rp_hash: &[u8; RP_HASH_BYTES],
    out: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<(u8, usize)>, Status> {
    let mut scan = Scan::new();
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some((n, entry)) = scan.read(index, out, p)? {
            if equal(entry.id, id) && equal(entry.rp_hash, rp_hash) {
                return Ok(Some((index, n)));
            }
        }
    }
    Ok(None)
}

/// Descending discovery shared by initial counting and getNextAssertion.
/// The cursor excludes the last returned slot, preserving legacy ordering.
#[inline(never)]
pub(super) fn discover(
    next: &mut u8,
    rp: &[u8; RP_HASH_BYTES],
    uv: bool,
    out: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<(u8, Id)>, Status> {
    while *next != 0 {
        *next -= 1;
        if let Some((_, entry)) = read(*next, out, p)? {
            if entry.rp_hash == rp
                && (uv || entry.id[1] & super::credential::CRED_PROTECT_MASK == 1)
                && super::credential::permitted_id(entry.id)
            {
                return Ok(Some((*next, *entry.id)));
            }
        }
    }
    Ok(None)
}

pub(super) fn count(
    out: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<u8, Status> {
    let mut count = 0;
    let mut scan = Scan::new();
    for index in 0..Record::CTAP_CREDENTIALS {
        if scan.read(index, out, p)?.is_some() {
            count += 1;
        }
    }
    Ok(count)
}

/// Small getNextAssertion cursor, not another request or key workspace.
pub(super) struct Assertion {
    pub rp: [u8; 32],
    pub client_hash: [u8; 32],
    pub next: u8,
    pub remaining: u8,
    pub uv: bool,
    pub up: bool,
    pub get_cred_blob: bool,
    pub third_party_payment: bool,
    pub hmac: super::hmac_secret::Prepared,
    pub continuation: canokey_ctap::session::IdleWindow<()>,
}
impl Assertion {
    pub const fn new() -> Self {
        Self {
            rp: [0; 32],
            client_hash: [0; 32],
            next: 0,
            remaining: 0,
            uv: false,
            up: false,
            get_cred_blob: false,
            third_party_payment: false,
            hmac: super::hmac_secret::Prepared::new(),
            continuation: canokey_ctap::session::IdleWindow::new(()),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    extern crate std;
    use super::*;

    const HEADER: usize = ID_BYTES + 32;
    // Binary user/blob fields deliberately contain non-UTF-8 bytes.
    const FIELDS: &[u8] = b"\x01r\x01\xff\x02\xc3\xa9\x04\xf0\x9f\x94\x91\x01\xfe";

    fn record() -> [u8; MAX_BYTES] {
        let mut bytes = [0; MAX_BYTES];
        bytes[1] = RESIDENT;
        bytes[HEADER..HEADER + FIELDS.len()].copy_from_slice(FIELDS);
        bytes
    }

    use crate::ports::{Crypto, CryptoError, Device, Storage};
    use std::vec::Vec;

    #[derive(Default)]
    pub(crate) struct Records {
        pub records: Vec<(u8, Vec<u8>)>,
        pub fail: Option<StorageError>,
        pub size_calls: usize,
        pub read_calls: usize,
        pub mutations: usize,
        aborts: usize,
        pub patch_bytes: usize,
        stage: Vec<u8>,
        stage_open: bool,
        fail_mutation: Option<usize>,
        commit_then_fail: bool,
    }
    impl Records {
        fn mutation(&mut self) -> Result<(), StorageError> {
            self.mutations += 1;
            if self.fail_mutation == Some(self.mutations) {
                Err(StorageError::Uncertain)
            } else {
                Ok(())
            }
        }
        fn publish(&mut self, id: Record, bytes: &[u8]) {
            self.records
                .retain(|(index, _)| Record::ctap_group(*index / 4) != Some(id));
            let header: &[u8; GROUP_HEADER] = bytes[..GROUP_HEADER].try_into().unwrap();
            let mut at = GROUP_HEADER;
            for member in 0..GROUP_MEMBERS {
                let n = member_length(header, member);
                if n != 0 {
                    let group = id.id() - Record::CTAP_GROUP_BASE;
                    self.records
                        .push((group * 4 + member as u8, bytes[at..at + n].to_vec()));
                }
                at += n;
            }
            assert_eq!(at, bytes.len());
        }
        fn group(&self, id: Record) -> Result<Vec<u8>, StorageError> {
            if let Some(error) = self.fail {
                return Err(error);
            }
            let mut header = [0; GROUP_HEADER];
            header[..4].copy_from_slice(GROUP_FORMAT);
            let mut body = Vec::new();
            for member in 0..4 {
                if let Some((_, bytes)) = self.records.iter().find(|(index, _)| {
                    Record::ctap_group(*index / 4) == Some(id) && usize::from(*index % 4) == member
                }) {
                    header[4 + member * 2..6 + member * 2]
                        .copy_from_slice(&(bytes.len() as u16).to_be_bytes());
                    body.extend_from_slice(bytes);
                }
            }
            if body.is_empty() {
                return Err(StorageError::Missing);
            }
            let mut bytes = header.to_vec();
            bytes.extend(body);
            Ok(bytes)
        }
    }
    impl Storage for Records {
        fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            let bytes = self.group(id)?;
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        fn size(&mut self, id: Record) -> Result<u32, StorageError> {
            assert!(!self.stage_open, "read closes the staging cache lease");
            self.size_calls += 1;
            Ok(self.group(id)?.len() as u32)
        }
        fn read_at(&mut self, id: Record, at: u32, out: &mut [u8]) -> Result<(), StorageError> {
            assert!(!self.stage_open, "read closes the staging cache lease");
            self.read_calls += 1;
            let bytes = self.group(id)?;
            let at = at as usize;
            let value = bytes
                .get(at..at + out.len())
                .ok_or(StorageError::Unavailable)?;
            out.copy_from_slice(value);
            Ok(())
        }
        fn replace_at(
            &mut self,
            id: Record,
            offset: u32,
            value: &[u8],
        ) -> Result<(), StorageError> {
            self.mutation()?;
            let mut bytes = self.group(id)?;
            bytes[offset as usize..offset as usize + value.len()].copy_from_slice(value);
            self.publish(id, &bytes);
            self.patch_bytes += value.len();
            Ok(())
        }
        fn stage_begin(&mut self) -> Result<(), StorageError> {
            self.mutation()?;
            self.stage.clear();
            self.stage_open = true;
            Ok(())
        }
        fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
            self.mutation()?;
            assert!(self.stage_open);
            self.stage.extend_from_slice(bytes);
            Ok(())
        }
        fn stage_commit(&mut self, id: Record) -> Result<(), StorageError> {
            self.mutation()?;
            let bytes = self.stage.clone();
            self.publish(id, &bytes);
            self.stage_open = false;
            if self.commit_then_fail {
                Err(StorageError::Uncertain)
            } else {
                Ok(())
            }
        }
        fn stage_abort(&mut self) {
            self.aborts += 1;
            self.stage_open = false;
            self.stage.clear();
        }
        fn remove(&mut self, id: Record) -> Result<(), StorageError> {
            self.mutation()?;
            self.records
                .retain(|(index, _)| Record::ctap_group(*index / 4) != Some(id));
            Ok(())
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            unreachable!()
        }
    }
    impl Crypto for Records {
        fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            unreachable!()
        }
    }
    impl Device for Records {
        fn progress(&mut self) -> bool {
            true
        }
        fn now(&mut self) -> u32 {
            0
        }
        fn serial(&mut self, _: &mut [u8; 4]) {
            unreachable!()
        }
        fn touched(&mut self) -> bool {
            false
        }
        fn led(&mut self, _: bool) {}
    }
    pub(crate) fn resident(index: u8, rp: u8, protection: u8) -> (u8, Vec<u8>) {
        let mut bytes = record()[..HEADER + FIELDS.len()].to_vec();
        bytes[1] |= protection;
        bytes[2] = index;
        bytes[ID_BYTES..HEADER].fill(rp);
        (index, bytes)
    }

    #[test]
    fn replacements_skip_identical_data_and_patch_only_the_target() {
        let mut storage = Records {
            records: (0..4).map(|i| resident(i, 7, 1)).collect(),
            ..Records::default()
        };
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut Records::default(),
            device: &mut Records::default(),
            memory: &canokey_ports::default_memory(),
        };
        let mut copy = [0xa5; COPY_BYTES];
        let mut value = resident(2, 7, 1).1;
        replace(2, &value, &mut copy, &mut p).unwrap();
        assert_eq!(p.storage.mutations, 0);
        assert!(copy.iter().all(|&b| b == 0));
        // Change one nonce byte without moving the CTG1 member boundaries.
        value[3] = 0x7a;
        replace(2, &value, &mut copy, &mut p).unwrap();
        assert_eq!(p.storage.mutations, 1);
        assert_eq!(p.storage.patch_bytes, value.len());
        assert_eq!(read(2, &mut copy, &mut p).unwrap().unwrap().1.id[3], 0x7a);
        for i in [0, 1, 3] {
            assert_eq!(read(i, &mut copy, &mut p).unwrap().unwrap().1.id[2], i);
        }
    }

    #[test]
    fn read_and_patch_failures_do_not_mutate_the_staging_file() {
        for read_failure in [false, true] {
            let mut storage = Records {
                records: std::vec![resident(0, 7, 1)],
                ..Records::default()
            };
            storage.fail = read_failure.then_some(StorageError::Unavailable);
            storage.fail_mutation = (!read_failure).then_some(1);
            let mut value = resident(0, 7, 1).1;
            value[3] = 0x7a;
            let mut copy = [0xa5; COPY_BYTES];
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut Records::default(),
                device: &mut Records::default(),
                memory: &canokey_ports::default_memory(),
            };
            assert_eq!(replace(0, &value, &mut copy, &mut p), Err(Status::Other));
            assert_eq!(p.storage.aborts, 0);
            assert_eq!(p.storage.mutations, usize::from(!read_failure));
            assert!(copy.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn maximum_group_rewrites_buffer_peers_before_staging_and_preserve_slots() {
        for target in 0..4 {
            for delete in [false, true] {
                let mut storage = Records::default();
                for index in 0..4 {
                    let mut bytes = [0; MAX_BYTES];
                    bytes[1] = RESIDENT;
                    bytes[2] = index;
                    encode_fields(
                        &mut bytes[HEADER..],
                        &[
                            &[b'r'; 32],
                            &[index; 64],
                            &[b'n'; 64],
                            &[b'd'; 64],
                            &[0xfe; 32],
                        ],
                    );
                    storage.records.push((index, bytes.to_vec()));
                }
                let original = storage.records.clone();
                let value = if delete {
                    Vec::new()
                } else {
                    resident(target, 7, 1).1
                };
                let mut copy = [0xa5; COPY_BYTES];
                let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut storage,
                    crypto: &mut Records::default(),
                    device: &mut Records::default(),
                    memory: &canokey_ports::default_memory(),
                };
                replace(target, &value, &mut copy, &mut p).unwrap();
                assert!(!p.storage.stage_open);
                assert!(copy.iter().all(|&b| b == 0));
                for (index, bytes) in original {
                    let loaded = load(index, &mut copy, &mut p).unwrap();
                    if index == target && delete {
                        assert!(loaded.is_none());
                    } else {
                        let expected = if index == target { &value } else { &bytes };
                        assert_eq!(&copy[..loaded.unwrap()], expected);
                    }
                }
            }
        }
    }

    #[test]
    fn failed_group_publication_is_reported_and_scratch_is_erased() {
        // begin, header, prefix, replacement, suffix, publish: every mutation boundary.
        for fault in 1..=7 {
            let original: Vec<_> = (0..4).map(|i| resident(i, 7, 1)).collect();
            let mut storage = Records {
                records: original.clone(),
                fail_mutation: Some(fault),
                commit_then_fail: fault == 7,
                ..Records::default()
            };
            let mut value = resident(1, 7, 1).1;
            value.pop();
            *value.last_mut().unwrap() = 0; // Empty optional blob, valid shorter record.
            let mut copy = [0xa5; COPY_BYTES];
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut Records::default(),
                device: &mut Records::default(),
                memory: &canokey_ports::default_memory(),
            };
            assert_eq!(replace(1, &value, &mut copy, &mut p), Err(Status::Other));
            assert!(copy.iter().all(|&b| b == 0));
            assert!(!p.storage.stage_open);
            if fault < 7 {
                assert_eq!(p.storage.records, original);
            } else {
                assert_eq!(
                    p.storage.records.iter().find(|(i, _)| *i == 1).unwrap().1,
                    value
                );
            }
        }
    }

    #[test]
    fn grouped_scan_halves_full_store_calls_without_changing_slot_data() {
        for cached in [false, true] {
            let mut storage = Records {
                records: (0..Record::CTAP_CREDENTIALS)
                    .map(|index| resident(index, index % 7, 1))
                    .collect(),
                ..Records::default()
            };
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut Records::default(),
                device: &mut Records::default(),
                memory: &canokey_ports::default_memory(),
            };
            let mut out = [0; MAX_BYTES];
            let mut scan = Scan::new();
            for index in 0..Record::CTAP_CREDENTIALS {
                let (_, entry) = if cached {
                    scan.read(index, &mut out, &mut p)
                } else {
                    read(index, &mut out, &mut p)
                }
                .unwrap()
                .unwrap();
                assert_eq!(entry.id[2], index);
                assert_eq!(entry.rp_hash, &[index % 7; RP_HASH_BYTES]);
            }
            let groups = usize::from(Record::CTAP_CREDENTIALS / Record::CTAP_GROUP_MEMBERS);
            let slots = usize::from(Record::CTAP_CREDENTIALS);
            assert_eq!(p.storage.size_calls, if cached { groups } else { slots });
            assert_eq!(
                p.storage.read_calls,
                if cached { groups + slots } else { 2 * slots }
            );
        }
    }

    #[test]
    fn grouped_scan_refreshes_between_requests_and_propagates_read_errors() {
        let mut storage = Records {
            records: std::vec![resident(0, 7, 1), resident(1, 8, 1)],
            ..Records::default()
        };
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut Records::default(),
            device: &mut Records::default(),
            memory: &canokey_ports::default_memory(),
        };
        let mut out = [0; MAX_BYTES];
        let mut scan = Scan::new();
        assert_eq!(
            scan.read(0, &mut out, &mut p).unwrap().unwrap().1.rp_hash,
            &[7; RP_HASH_BYTES]
        );
        p.storage.fail = Some(StorageError::Unavailable);
        assert!(matches!(scan.read(1, &mut out, &mut p), Err(Status::Other)));
        assert!(matches!(scan.read(4, &mut out, &mut p), Err(Status::Other)));
        p.storage.fail = None;
        // A failed switch must invalidate the old tag even if its header was
        // overwritten before the error. Reusing this scan must reload group 0.
        assert_eq!(
            scan.read(0, &mut out, &mut p).unwrap().unwrap().1.rp_hash,
            &[7; RP_HASH_BYTES]
        );
        drop(scan);
        p.storage.fail = None;
        p.storage.records.clear();
        let mut scan = Scan::new();
        assert!(scan.read(0, &mut out, &mut p).unwrap().is_none());
        drop(scan);
        p.storage.records.push(resident(0, 9, 1));
        let mut scan = Scan::new();
        assert_eq!(
            scan.read(0, &mut out, &mut p).unwrap().unwrap().1.rp_hash,
            &[9; RP_HASH_BYTES]
        );
        drop(scan);
        p.storage.records[0].1.truncate(HEADER);
        assert!(matches!(
            Scan::new().read(0, &mut out, &mut p),
            Err(Status::Other)
        ));
    }

    #[test]
    fn discovery_preserves_descending_slots_rp_and_uv_filters() {
        let mut storage = Records {
            records: std::vec![
                resident(1, 7, 1),
                resident(4, 7, 3),
                resident(7, 8, 1),
                resident(99, 7, 1)
            ],
            ..Records::default()
        };
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut Records::default(),
            device: &mut Records::default(),
            memory: &canokey_ports::default_memory(),
        };
        let mut out = [0; MAX_BYTES];
        assert_eq!(count(&mut out, &mut p), Ok(4));
        for uv in [false, true] {
            let mut next = Record::CTAP_CREDENTIALS;
            let mut found = Vec::new();
            while let Some((index, id)) =
                discover(&mut next, &[7; 32], uv, &mut out, &mut p).unwrap()
            {
                assert_eq!(id[2], index);
                found.push(index);
            }
            assert_eq!(
                found,
                if uv {
                    std::vec![99, 4, 1]
                } else {
                    std::vec![99, 1]
                }
            );
            assert!(
                discover(&mut next, &[7; 32], uv, &mut out, &mut p)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn resident_reads_distinguish_empty_slots_corruption_and_io_failure() {
        let mut storage = Records {
            records: std::vec![resident(4, 7, 1)],
            ..Records::default()
        };
        let mut out = [0; MAX_BYTES];
        for case in 0..4 {
            if case == 1 {
                storage.records[0].1.truncate(HEADER);
            }
            if case == 2 {
                storage.fail = Some(StorageError::Unavailable);
            }
            if case == 3 {
                storage.fail = Some(StorageError::Uncertain);
            }
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut Records::default(),
                device: &mut Records::default(),
                memory: &canokey_ports::default_memory(),
            };
            if case == 0 {
                assert!(read(0, &mut out, &mut p).unwrap().is_none());
                let (n, entry) = read(4, &mut out, &mut p).unwrap().unwrap();
                assert_eq!(n, HEADER + FIELDS.len());
                assert_eq!(entry.rp_hash, &[7; 32]);
            } else {
                assert!(matches!(read(4, &mut out, &mut p), Err(Status::Other)));
                assert_eq!(count(&mut out, &mut p), Err(Status::Other));
            }
        }
    }

    #[test]
    fn stored_text_keeps_unicode_and_binary_fields_distinct() {
        for (rp, expected) in [
            ("example.com", "example.com"),
            (
                "myfidousingwebsite.hostingprovider.net",
                "…ngwebsite.hostingprovider.net",
            ),
            (
                "mygreatsite.hostingprovider.info",
                "mygreatsite.hostingprovider.info",
            ),
            (
                "otherprotocol://myfidousingwebsite.hostingprovider.net",
                "otherprotocol:…ingprovider.net",
            ),
            (
                "veryexcessivelylargeprotocolname://example.com",
                "veryexcessivelylargeprotocolname",
            ),
            ("界界界界界界界界界界界界", "…界界界界界界界界界"),
        ] {
            let mut out = [0; 32];
            assert_eq!(display_rp(rp.as_bytes(), &mut out), expected.as_bytes());
        }
        let bytes = record();
        let entry = decode(&bytes[..HEADER + FIELDS.len()]).unwrap();
        assert_eq!(entry.rp, "r");
        assert_eq!(entry.user, b"\xff");
        assert_eq!(entry.name, "é");
        assert_eq!(entry.display, "🔑");
        assert_eq!(entry.blob, b"\xfe");

        let mut out = [0xa5; MAX_BYTES];
        let n = encode_fields(
            &mut out,
            &[
                entry.rp.as_bytes(),
                entry.user,
                entry.name.as_bytes(),
                entry.display.as_bytes(),
                entry.blob,
            ],
        );
        assert_eq!(&out[..n], FIELDS);
        assert!(out[n..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn malformed_stored_text_and_record_boundaries_are_rejected() {
        let bytes = record();
        let length = HEADER + FIELDS.len();
        for cut in 0..length {
            assert!(matches!(decode(&bytes[..cut]), Err(Status::Other)));
        }
        assert!(matches!(decode(&bytes[..length + 1]), Err(Status::Other)));
        for offset in [1, 5, 8] {
            let mut corrupt = bytes;
            corrupt[HEADER + offset] = 0xff;
            assert!(matches!(decode(&corrupt[..length]), Err(Status::Other)));
        }
        for (offset, invalid) in [(0, 33), (2, 65), (4, 65), (7, 65), (12, 33)] {
            let mut corrupt = bytes;
            corrupt[HEADER + offset] = invalid;
            assert!(matches!(decode(&corrupt[..length]), Err(Status::Other)));
        }
        let mut non_resident = bytes;
        non_resident[1] = 0;
        assert!(matches!(
            decode(&non_resident[..length]),
            Err(Status::Other)
        ));
    }

    #[test]
    fn record_fields_fit_at_all_capacity_limits() {
        let mut bytes = [0; MAX_BYTES];
        bytes[1] = RESIDENT;
        let n = encode_fields(
            &mut bytes[HEADER..],
            &[
                &[b'r'; 32],
                &[0xff; 64],
                &[b'n'; 64],
                &[b'd'; 64],
                &[0xfe; 32],
            ],
        );
        assert_eq!(HEADER + n, MAX_BYTES);
        let entry = decode(&bytes).unwrap();
        assert_eq!(entry.rp, "r".repeat(32));
        assert_eq!(entry.user, &[0xff; 64]);
        assert_eq!(entry.name, "n".repeat(64));
        assert_eq!(entry.display, "d".repeat(64));
        assert_eq!(entry.blob, &[0xfe; 32]);

        // Empty optional fields remain valid, including after a Unicode prefix
        // is cut at a persistence limit in the middle of a code point.
        let n = encode_fields(
            &mut bytes[HEADER..],
            &[b"r", b"u", text_prefix(&"é".as_bytes()[..1]), b"", b""],
        );
        let entry = decode(&bytes[..HEADER + n]).unwrap();
        assert_eq!((entry.name, entry.display, entry.blob), ("", "", &b""[..]));
    }
}
