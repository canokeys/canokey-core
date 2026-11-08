// SPDX-License-Identifier: Apache-2.0
//! CTG1 resident member codec; products own storage, capacity and authorization.

pub const ID_BYTES: usize = 34;
pub const RESIDENT: u8 = 0x04;
pub const RP_HASH_BYTES: usize = 32;
pub const RP_DISPLAY_BYTES: usize = 32;
pub const USER_ID_BYTES: usize = 64;
pub const USER_NAME_BYTES: usize = 64;
pub const USER_DISPLAY_BYTES: usize = 64;
pub const CRED_BLOB_BYTES: usize = 32;
pub const FIELD_COUNT: usize = 5;
pub const FIXED_BYTES: usize = ID_BYTES + RP_HASH_BYTES;
pub const FIELD_LIMITS: [usize; FIELD_COUNT] = [
    RP_DISPLAY_BYTES,
    USER_ID_BYTES,
    USER_NAME_BYTES,
    USER_DISPLAY_BYTES,
    CRED_BLOB_BYTES,
];
pub const MIN_BYTES: usize = FIXED_BYTES + FIELD_COUNT;
pub const MAX_BYTES: usize = MIN_BYTES
    + RP_DISPLAY_BYTES
    + USER_ID_BYTES
    + USER_NAME_BYTES
    + USER_DISPLAY_BYTES
    + CRED_BLOB_BYTES;

/// Malformed persisted member; each product maps this to its recovery status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRecord;

// Member layout: 34-byte ID, 32-byte RP hash, then five u8-length-prefixed
// fields: RP display, user ID, user name, user display name, credential blob.
// This is the CanoKey CTG1 storage format, not a CTAP wire representation.
pub struct Entry<'a> {
    pub id: &'a [u8; ID_BYTES],
    pub rp_hash: &'a [u8; RP_HASH_BYTES],
    pub rp: &'a str,
    pub user: &'a [u8],
    pub name: &'a str,
    pub display: &'a str,
    pub blob: &'a [u8],
}
impl<'a> Entry<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, InvalidRecord> {
        if bytes.len() < FIXED_BYTES {
            return Err(InvalidRecord);
        }
        let id: &[u8; ID_BYTES] = bytes[..ID_BYTES].try_into().unwrap();
        let rp_hash = bytes[ID_BYTES..FIXED_BYTES].try_into().unwrap();
        let mut rest = &bytes[FIXED_BYTES..];
        let rp = take(&mut rest, RP_DISPLAY_BYTES)?;
        let user = take(&mut rest, USER_ID_BYTES)?;
        let name = take(&mut rest, USER_NAME_BYTES)?;
        let display = take(&mut rest, USER_DISPLAY_BYTES)?;
        let blob = take(&mut rest, CRED_BLOB_BYTES)?;
        if user.is_empty() || !rest.is_empty() || id[1] & RESIDENT == 0x00 {
            return Err(InvalidRecord);
        }
        let rp = core::str::from_utf8(rp).map_err(|_| InvalidRecord)?;
        let name = core::str::from_utf8(name).map_err(|_| InvalidRecord)?;
        let display = core::str::from_utf8(display).map_err(|_| InvalidRecord)?;
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
            return Err(InvalidRecord);
        }
        Ok(entry)
    }
}
fn take<'a>(rest: &mut &'a [u8], limit: usize) -> Result<&'a [u8], InvalidRecord> {
    let n = usize::from(*rest.first().ok_or(InvalidRecord)?);
    if n > limit || rest.len() < 1 + n {
        return Err(InvalidRecord);
    }
    let value = &rest[1..1 + n];
    *rest = &rest[1 + n..];
    Ok(value)
}
pub fn text_prefix(bytes: &[u8]) -> &[u8] {
    match core::str::from_utf8(bytes) {
        Ok(_) => bytes,
        Err(error) => &bytes[..error.valid_up_to()],
    }
}
// Preserve scheme and domain suffix for the legacy 32-byte RP display field.
// Hashing and credential matching always use the complete original RP ID.
pub fn display_rp<'a>(rp: &'a [u8], out: &'a mut [u8; RP_DISPLAY_BYTES]) -> &'a [u8] {
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

/// Encode fields already bounded by FIELD_LIMITS into sufficient backing.
/// Callers validate required fields and UTF-8 before publishing the member.
pub fn encode_fields(out: &mut [u8], fields: &[&[u8]; FIELD_COUNT]) -> usize {
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
