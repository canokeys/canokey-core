// SPDX-License-Identifier: Apache-2.0
//! CTG1 layout, replacement accounting and synchronous update mechanisms.
pub mod update;
use super::{InvalidRecord, MAX_BYTES, MIN_BYTES};

pub const MEMBERS: usize = 4;
pub const FORMAT: &[u8; 4] = b"CTG1";
const LENGTH_BYTES: usize = core::mem::size_of::<u16>();
// CTG1 v1: four magic bytes, then four big-endian u16 member byte lengths.
// Zero marks an absent member; present payloads follow in logical slot order.
pub const HEADER_BYTES: usize = FORMAT.len() + MEMBERS * LENGTH_BYTES;
pub const MAX_GROUP_BYTES: usize = HEADER_BYTES + MEMBERS * MAX_BYTES;
pub type Header = [u8; HEADER_BYTES];

pub fn empty() -> Header {
    let mut header = [0x00; HEADER_BYTES];
    header[..FORMAT.len()].copy_from_slice(FORMAT);
    header
}

/// Validate a present file. A missing file uses empty() instead; a persisted
/// header without members is corrupt, since deleting the last member removes it.
pub fn validate(header: &Header, file_bytes: usize) -> Result<(), InvalidRecord> {
    if &header[..FORMAT.len()] != FORMAT {
        return Err(InvalidRecord);
    }
    let mut total = HEADER_BYTES;
    for member in 0..MEMBERS {
        let length = member_length(header, member);
        if length > MAX_BYTES || length != 0 && length < MIN_BYTES {
            return Err(InvalidRecord);
        }
        total += length;
    }
    if total != file_bytes || total == HEADER_BYTES {
        return Err(InvalidRecord);
    }
    Ok(())
}

/// The owner admits member < MEMBERS before indexing its fixed group header.
pub fn member_length(header: &Header, member: usize) -> usize {
    let offset = FORMAT.len() + member * LENGTH_BYTES;
    usize::from(u16::from_be_bytes([header[offset], header[offset + 1]]))
}

pub fn member_offset(header: &Header, member: usize) -> usize {
    HEADER_BYTES
        + (0..member)
            .map(|index| member_length(header, index))
            .sum::<usize>()
}

/// Size/offset planning is shared by buffered and single-member scratch owners.
/// The owner validates the existing header (or supplies empty()) and replacement
/// payload before applying this plan. It owns patch/staging/commit semantics.
pub struct Replacement {
    pub offset: usize,
    pub old_length: usize,
    pub total_bytes: usize,
}
impl Replacement {
    pub fn new(header: &Header, member: usize, length: usize) -> Result<Self, InvalidRecord> {
        if member >= MEMBERS || length > MAX_BYTES || length != 0 && length < MIN_BYTES {
            return Err(InvalidRecord);
        }
        let old_length = member_length(header, member);
        let total_bytes = member_offset(header, MEMBERS) - old_length + length;
        Ok(Self {
            offset: member_offset(header, member),
            old_length,
            total_bytes,
        })
    }
    pub fn set_length(header: &mut Header, member: usize, length: usize) {
        let offset = FORMAT.len() + member * LENGTH_BYTES;
        header[offset..offset + LENGTH_BYTES].copy_from_slice(&(length as u16).to_be_bytes());
    }
}
