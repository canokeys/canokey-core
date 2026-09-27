// SPDX-License-Identifier: Apache-2.0
//! Persist only active RSA limbs; expand into the fixed native workspace on load.
use crate::ports::key_layout as layout;
use crate::ports::{Record, StorageError};

// width is a byte count: one RSA prime/CRT component, an EC scalar, or a PQ
// seed. RSA disk order is e,p,q,dp,dq,qinv; each native slot has 256-byte capacity
// but only its active width is persisted. Public keys are derived, not stored.
pub fn length(rsa: bool, width: usize) -> usize {
    if width > layout::RSA_LIMB_BYTES {
        return 0;
    }
    if rsa {
        layout::EXPONENT_BYTES + layout::RSA_LIMBS * width
    } else {
        width
    }
}
pub fn load(
    storage: &mut crate::ports::StoragePort<'_>,
    record: Record,
    mut offset: u32,
    rsa: bool,
    width: usize,
    key: &mut [u8; crate::ports::key_layout::SIZE],
) -> Result<(), StorageError> {
    if width > layout::RSA_LIMB_BYTES {
        return Err(StorageError::Unavailable);
    }
    key.fill(0);
    if !rsa {
        return storage.read_at(record, offset, &mut key[..width]);
    }
    storage.read_at(record, offset, &mut key[..layout::EXPONENT_BYTES])?;
    offset += layout::EXPONENT_BYTES as u32;
    for component in key[layout::P..]
        .as_chunks_mut::<{ layout::RSA_LIMB_BYTES }>()
        .0
    {
        storage.read_at(record, offset, &mut component[..width])?;
        offset += width as u32;
    }
    Ok(())
}
pub fn stage(
    storage: &mut crate::ports::StoragePort<'_>,
    rsa: bool,
    width: usize,
    key: &[u8; crate::ports::key_layout::SIZE],
    metadata: &[u8],
) -> Result<(), StorageError> {
    if width > layout::RSA_LIMB_BYTES {
        return Err(StorageError::Unavailable);
    }
    if !rsa {
        return storage.stage_parts(&[&[2], &key[..width], metadata]);
    }
    let mut parts: [&[u8]; 8] = [&[]; 8];
    parts[0] = &[2]; // Explicit layout discriminator, before arbitrary key bytes.
    parts[1] = &key[..layout::EXPONENT_BYTES];
    for (i, component) in key[layout::P..]
        .as_chunks::<{ layout::RSA_LIMB_BYTES }>()
        .0
        .iter()
        .enumerate()
    {
        parts[i + 2] = &component[..width];
    }
    parts[7] = metadata;
    storage.stage_parts(&parts)
}
