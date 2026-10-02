// SPDX-License-Identifier: Apache-2.0
//! Four logical credentials share one atomically published record.
use super::{
    Status,
    credential::{ID_BYTES, Id},
    credential_request::{CRED_BLOB_BYTES, Parameters},
    crypto::equal,
};
use crate::ports::{Platform, Record, StorageError};

pub(super) const RESIDENT: u8 = 0x04;
pub(super) const LARGE_BLOB_KEY: u8 = 0x08;
const RP_HASH_BYTES: usize = 32;
const RP_DISPLAY_BYTES: usize = 32;
const USER_ID_BYTES: usize = 64;
const USER_NAME_BYTES: usize = 64;
const USER_DISPLAY_BYTES: usize = 64;
const FIELD_COUNT: usize = 5;
const FIXED_BYTES: usize = ID_BYTES + RP_HASH_BYTES;
pub(super) const MAX_BYTES: usize = FIXED_BYTES
    + FIELD_COUNT
    + RP_DISPLAY_BYTES
    + USER_ID_BYTES
    + USER_NAME_BYTES
    + USER_DISPLAY_BYTES
    + CRED_BLOB_BYTES;
const GROUP_MEMBERS: usize = Record::CTAP_GROUP_MEMBERS as usize;
const MEMBER_LENGTH_BYTES: usize = core::mem::size_of::<u16>();
// CTG1 identifies version 1: four big-endian u16 lengths (zero is absent),
// followed by present credential payloads in logical member order.
const GROUP_FORMAT: &[u8; 4] = b"CTG1";
const GROUP_HEADER: usize = GROUP_FORMAT.len() + GROUP_MEMBERS * MEMBER_LENGTH_BYTES;

fn group_header(record: Record, p: &mut Platform<'_>) -> Result<[u8; GROUP_HEADER], Status> {
    let mut header = [0; GROUP_HEADER];
    header[..GROUP_FORMAT.len()].copy_from_slice(GROUP_FORMAT);
    let size = match p.storage.size(record) {
        Ok(n) => n,
        Err(StorageError::Missing) => return Ok(header),
        Err(_) => return Err(Status::Other),
    };
    p.storage
        .read_at(record, 0, &mut header)
        .map_err(|_| Status::Other)?;
    if &header[..GROUP_FORMAT.len()] != GROUP_FORMAT {
        return Err(Status::Other);
    }
    let mut total = GROUP_HEADER as u32;
    for member in 0..GROUP_MEMBERS {
        let n = member_length(&header, member);
        if n > MAX_BYTES || (n != 0 && n < FIXED_BYTES + FIELD_COUNT) {
            return Err(Status::Other);
        }
        total += n as u32;
    }
    if total != size || total == GROUP_HEADER as u32 {
        return Err(Status::Other);
    }
    Ok(header)
}
fn member_length(header: &[u8; GROUP_HEADER], member: usize) -> usize {
    let at = GROUP_FORMAT.len() + member * MEMBER_LENGTH_BYTES;
    usize::from(u16::from_be_bytes([header[at], header[at + 1]]))
}

/// Copy validated unchanged members using the caller's disjoint workspace.
pub(super) fn replace(
    index: u8,
    value: &[u8],
    copy: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    let record = Record::ctap_group(index / Record::CTAP_GROUP_MEMBERS).ok_or(Status::Other)?;
    if !value.is_empty() {
        if value.len() > MAX_BYTES {
            return Err(Status::Other);
        }
        Entry::decode(value)?;
    }
    let mut header = group_header(record, p)?;
    let lengths = core::array::from_fn::<_, GROUP_MEMBERS, _>(|i| member_length(&header, i));
    let target = usize::from(index % Record::CTAP_GROUP_MEMBERS);
    let length_offset = GROUP_FORMAT.len() + target * MEMBER_LENGTH_BYTES;
    header[length_offset..length_offset + MEMBER_LENGTH_BYTES]
        .copy_from_slice(&(value.len() as u16).to_be_bytes());
    let result = (|| {
        if value.is_empty()
            && lengths
                .iter()
                .enumerate()
                .all(|(i, &n)| i == target || n == 0)
        {
            return p.storage.remove(record).map_err(|_| Status::Other);
        }
        p.storage.stage_begin().map_err(|_| Status::Other)?;
        p.storage.stage_append(&header).map_err(|_| Status::Other)?;
        let mut offset = GROUP_HEADER as u32;
        for (member, &n) in lengths.iter().enumerate() {
            if n != 0 {
                p.storage
                    .read_at(record, offset, &mut copy[..n])
                    .map_err(|_| Status::Other)?;
                Entry::decode(&copy[..n])?;
            }
            let bytes = if member == target { value } else { &copy[..n] };
            p.storage.stage_append(bytes).map_err(|_| Status::Other)?;
            offset += n as u32;
        }
        p.storage.stage_commit(record).map_err(|_| Status::Other)
    })();
    p.memory.wipe(copy);
    if result.is_err() {
        p.storage.stage_abort();
    }
    result
}
pub(super) struct Entry<'a> {
    pub id: &'a Id,
    pub rp_hash: &'a [u8; RP_HASH_BYTES],
    pub rp: &'a str,
    pub user: &'a [u8],
    pub name: &'a str,
    pub display: &'a str,
    pub blob: &'a [u8],
}
impl<'a> Entry<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() < FIXED_BYTES {
            return Err(Status::Other);
        }
        let id: &Id = bytes[..ID_BYTES].try_into().unwrap();
        let rp_hash = bytes[ID_BYTES..FIXED_BYTES].try_into().unwrap();
        let mut rest = &bytes[FIXED_BYTES..];
        let rp = take(&mut rest, RP_DISPLAY_BYTES)?;
        let user = take(&mut rest, USER_ID_BYTES)?;
        let name = take(&mut rest, USER_NAME_BYTES)?;
        let display = take(&mut rest, USER_DISPLAY_BYTES)?;
        let blob = take(&mut rest, CRED_BLOB_BYTES)?;
        if user.is_empty() || !rest.is_empty() || id[1] & RESIDENT == 0 {
            return Err(Status::Other);
        }
        let rp = core::str::from_utf8(rp).map_err(|_| Status::Other)?;
        let name = core::str::from_utf8(name).map_err(|_| Status::Other)?;
        let display = core::str::from_utf8(display).map_err(|_| Status::Other)?;
        let entry = Self {
            id,
            rp_hash,
            rp,
            user,
            name,
            display,
            blob,
        };
        if entry.rp.is_empty() {
            return Err(Status::Other);
        }
        Ok(entry)
    }
}
fn take<'a>(rest: &mut &'a [u8], limit: usize) -> Result<&'a [u8], Status> {
    let n = usize::from(*rest.first().ok_or(Status::Other)?);
    if n > limit || rest.len() < 1 + n {
        return Err(Status::Other);
    }
    let value = &rest[1..1 + n];
    *rest = &rest[1 + n..];
    Ok(value)
}
pub(super) fn text_prefix(bytes: &[u8]) -> &[u8] {
    match core::str::from_utf8(bytes) {
        Ok(_) => bytes,
        Err(error) => &bytes[..error.valid_up_to()],
    }
}
// Preserve scheme and domain suffix for the legacy 32-byte RP display field.
// Hashing and credential matching always use the complete original RP ID.
fn display_rp<'a>(rp: &'a [u8], out: &'a mut [u8; RP_DISPLAY_BYTES]) -> &'a [u8] {
    if rp.len() <= out.len() {
        return rp;
    }
    let prefix = rp.iter().position(|&b| b == b':').map_or(0, |n| n + 1);
    let prefix = text_prefix(&rp[..prefix.min(out.len())]);
    let mut used = prefix.len();
    out[..used].copy_from_slice(prefix);
    if out.len() - used >= 3 {
        out[used..used + 3].copy_from_slice("…".as_bytes());
        used += 3;
        let mut start = rp.len() - (out.len() - used);
        // Never start the suffix inside a UTF-8 code point.
        while start < rp.len() && rp[start] & 0xc0 == 0x80 {
            start += 1;
        }
        out[used..used + rp.len() - start].copy_from_slice(&rp[start..]);
        used += rp.len() - start;
    }
    &out[..used]
}

pub(super) fn load(
    index: u8,
    out: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<usize>, Status> {
    let record = Record::ctap_group(index / Record::CTAP_GROUP_MEMBERS).ok_or(Status::Other)?;
    let header = group_header(record, p)?;
    let member = usize::from(index % Record::CTAP_GROUP_MEMBERS);
    let n = member_length(&header, member);
    if n == 0 {
        return Ok(None);
    }
    let offset = GROUP_HEADER
        + (0..member)
            .map(|i| member_length(&header, i))
            .sum::<usize>();
    p.storage
        .read_at(record, offset as u32, &mut out[..n])
        .map_err(|_| Status::Other)?;
    Ok(Some(n))
}
/// Load and validate one occupied resident slot without copying its fields.
#[inline(never)]
pub(super) fn read<'a>(
    index: u8,
    out: &'a mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<(usize, Entry<'a>)>, Status> {
    let Some(n) = load(index, out, p)? else {
        return Ok(None);
    };
    Ok(Some((n, Entry::decode(&out[..n])?)))
}
pub(super) fn store(
    params: &Parameters,
    id: &Id,
    rp_hash: &[u8; RP_HASH_BYTES],
    out: &mut [u8],
    copy: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    let mut slot = None;
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some((_, entry)) = read(index, out, p)? {
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

/// Encode the five bounded variable fields shared by creation and user updates.
pub(super) fn encode_fields(out: &mut [u8], fields: &[&[u8]; FIELD_COUNT]) -> usize {
    let capacity = out.len();
    let mut tail = out;
    for field in fields {
        let (length, remaining) = tail.split_first_mut().unwrap();
        *length = field.len() as u8;
        let (value, remaining) = remaining.split_at_mut(field.len());
        value.copy_from_slice(field);
        tail = remaining;
    }
    capacity - tail.len()
}

pub(super) fn find(
    id: &Id,
    rp_hash: &[u8; RP_HASH_BYTES],
    out: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<Option<(u8, usize)>, Status> {
    for index in 0..Record::CTAP_CREDENTIALS {
        if let Some((n, entry)) = read(index, out, p)? {
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
    p: &mut Platform<'_>,
) -> Result<Option<(u8, Id)>, Status> {
    while *next != 0 {
        *next -= 1;
        if let Some((_, entry)) = read(*next, out, p)? {
            if entry.rp_hash == rp
                && (uv || entry.id[1] & 3 == 1)
                && super::credential::permitted_id(entry.id)
            {
                return Ok(Some((*next, *entry.id)));
            }
        }
    }
    Ok(None)
}

pub(super) fn count(out: &mut [u8], p: &mut Platform<'_>) -> Result<u8, Status> {
    let mut count = 0;
    for index in 0..Record::CTAP_CREDENTIALS {
        if read(index, out, p)?.is_some() {
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
    pub started: u32,
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
            started: 0,
        }
    }
}

#[cfg(test)]
mod tests {
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
    struct Records {
        records: Vec<(u8, Vec<u8>)>,
        fail: Option<StorageError>,
    }
    impl Records {
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
            Ok(self.group(id)?.len() as u32)
        }
        fn read_at(&mut self, id: Record, at: u32, out: &mut [u8]) -> Result<(), StorageError> {
            let bytes = self.group(id)?;
            let at = at as usize;
            let value = bytes
                .get(at..at + out.len())
                .ok_or(StorageError::Unavailable)?;
            out.copy_from_slice(value);
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
    fn resident(index: u8, rp: u8, protection: u8) -> (u8, Vec<u8>) {
        let mut bytes = record()[..HEADER + FIELDS.len()].to_vec();
        bytes[1] |= protection;
        bytes[2] = index;
        bytes[ID_BYTES..HEADER].fill(rp);
        (index, bytes)
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
        let mut p = Platform {
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
            let mut p = Platform {
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
        let entry = Entry::decode(&bytes[..HEADER + FIELDS.len()]).unwrap();
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
            assert!(matches!(Entry::decode(&bytes[..cut]), Err(Status::Other)));
        }
        assert!(matches!(
            Entry::decode(&bytes[..length + 1]),
            Err(Status::Other)
        ));
        for offset in [1, 5, 8] {
            let mut corrupt = bytes;
            corrupt[HEADER + offset] = 0xff;
            assert!(matches!(
                Entry::decode(&corrupt[..length]),
                Err(Status::Other)
            ));
        }
        for (offset, invalid) in [(0, 33), (2, 65), (4, 65), (7, 65), (12, 33)] {
            let mut corrupt = bytes;
            corrupt[HEADER + offset] = invalid;
            assert!(matches!(
                Entry::decode(&corrupt[..length]),
                Err(Status::Other)
            ));
        }
        let mut non_resident = bytes;
        non_resident[1] = 0;
        assert!(matches!(
            Entry::decode(&non_resident[..length]),
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
        let entry = Entry::decode(&bytes).unwrap();
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
        let entry = Entry::decode(&bytes[..HEADER + n]).unwrap();
        assert_eq!((entry.name, entry.display, entry.blob), ("", "", &b""[..]));
    }
}
