// Fixed Core cd92e240 resident codec projection; source sha256: f8e47c6d12832f54eff904a20bea9aff9728d2eef547f772d39883bedea11c3b
// Only visibility/import/type context is projected. Do not reformat this snapshot.
#![allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Status { Other }
const ID_BYTES: usize = 34;
type Id = [u8; ID_BYTES];
const RP_HASH_BYTES: usize = 32;
const RP_DISPLAY_BYTES: usize = 32;
const USER_ID_BYTES: usize = 64;
const USER_NAME_BYTES: usize = 64;
const USER_DISPLAY_BYTES: usize = 64;
const CRED_BLOB_BYTES: usize = 32;
const FIELD_COUNT: usize = 5;
const FIXED_BYTES: usize = ID_BYTES + RP_HASH_BYTES;
const RESIDENT: u8 = 0x04;
pub struct Entry<'a> {
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

/// Encode the five bounded variable fields shared by creation and user updates.
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
