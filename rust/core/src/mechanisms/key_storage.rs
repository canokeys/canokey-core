// SPDX-License-Identifier: Apache-2.0
//! Persist only active RSA limbs; expand into the fixed native workspace on load.
use crate::ports::{Record, Storage, StorageError};

pub fn length(rsa: bool, width: usize) -> usize {
    if rsa { 4 + 5 * width } else { width }
}
pub fn load(
    storage: &mut dyn Storage,
    record: Record,
    mut offset: u32,
    rsa: bool,
    width: usize,
    key: &mut [u8; 1284],
) -> Result<(), StorageError> {
    key.fill(0);
    if !rsa {
        return storage.read_at(record, offset, &mut key[..width]);
    }
    storage.read_at(record, offset, &mut key[..4])?;
    offset += 4;
    for component in key[4..].chunks_exact_mut(256) {
        storage.read_at(record, offset, &mut component[..width])?;
        offset += width as u32;
    }
    Ok(())
}
pub fn append(
    storage: &mut dyn Storage,
    rsa: bool,
    width: usize,
    key: &[u8; 1284],
) -> Result<(), StorageError> {
    if !rsa {
        return storage.stage_append(&key[..width]);
    }
    storage.stage_append(&key[..4])?;
    for component in key[4..].chunks_exact(256) {
        storage.stage_append(&component[..width])?;
    }
    Ok(())
}
