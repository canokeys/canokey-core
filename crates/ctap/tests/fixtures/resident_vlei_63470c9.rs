// Fixed authenticator 63470c9 resident codec projection; source sha256: acde37f5dc1877c43b07936ac6f9e2d36703798d5fc8c00af2163db8c20ea382
// Only visibility/import context is projected. Do not reformat this snapshot.
#![allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Status { RecoveryRequired }
const ID_BYTES: usize = 34;
const MIN_RECORD_BYTES: usize = ID_BYTES + 32 + 5;
const RECORD_BYTES: usize = MIN_RECORD_BYTES + 32 + 64 + 64 + 64 + 32;
const FIXED_BYTES: usize = ID_BYTES + 32;
const FIELD_LIMITS: [usize; 5] = [32, 64, 64, 64, 32];
const RP_DISPLAY: usize = 0;
const USER_ID: usize = 1;
const USER_NAME: usize = 2;
const USER_DISPLAY: usize = 3;
pub fn validate(bytes: &[u8]) -> Result<(), Status> {
    // Credential ID byte 1 bit 2 (04) marks a discoverable/resident credential.
    if bytes.len() < MIN_RECORD_BYTES || bytes.len() > RECORD_BYTES || bytes[1] & 0x04 == 0x00 {
        return Err(Status::RecoveryRequired);
    }
    let mut at = FIXED_BYTES;
    for (field, limit) in FIELD_LIMITS.iter().enumerate() {
        let n = usize::from(*bytes.get(at).ok_or(Status::RecoveryRequired)?);
        let value = bytes
            .get(at + 1..at + 1 + n)
            .ok_or(Status::RecoveryRequired)?;
        if n > *limit || matches!(field, RP_DISPLAY | USER_ID) && n == 0 {
            return Err(Status::RecoveryRequired);
        }
        if matches!(field, RP_DISPLAY | USER_NAME | USER_DISPLAY)
            && core::str::from_utf8(value).is_err()
        {
            return Err(Status::RecoveryRequired);
        }
        at += 1 + n;
    }
    if at != bytes.len() {
        return Err(Status::RecoveryRequired);
    }
    Ok(())
}
const RP_DISPLAY_BYTES: usize = 32;
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
        // UTF-8 continuation bytes have prefix 10xxxxxx; advance to a scalar boundary.
        while start < rp.len() && rp[start] & 0xc0 == 0x80 {
            start += 1;
        }
        out[used..used + rp.len() - start].copy_from_slice(&rp[start..]);
        used += rp.len() - start;
    }
    &out[..used]
}
