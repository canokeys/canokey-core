// SPDX-License-Identifier: Apache-2.0
//! Persist only active RSA limbs; expand into the fixed native workspace on load.
use crate::ports::key_layout as layout;
use crate::ports::{Record, Storage, StorageError};

const RECORD_HEADER_BYTES: usize = 1;
// The leading byte distinguishes compact RSA/EC/PQ records from legacy layouts.
const KEY_FORMAT_VERSION: u8 = 0x02;

#[inline(always)]
pub fn read_footer<const N: usize>(
    storage: &mut (impl Storage + ?Sized),
    record: Record,
    total: u32,
    version: u8,
    footer: &mut [u8; N],
    validate: impl FnOnce(&[u8; N], u32) -> bool,
) -> Result<bool, StorageError> {
    let mut discriminator = [0];
    storage.read_at(record, 0, &mut discriminator)?;
    if discriminator[0] != version || total < (RECORD_HEADER_BYTES + N) as u32 {
        return Ok(false);
    }
    storage.read_at(record, total - N as u32, footer)?;
    Ok(validate(footer, total))
}

#[inline(always)]
pub fn commit(
    storage: &mut (impl Storage + ?Sized),
    record: Record,
    rsa: bool,
    width: usize,
    key: &[u8; layout::SIZE],
    metadata: &[u8],
) -> Result<(), StorageError> {
    let result =
        stage(storage, rsa, width, key, metadata).and_then(|()| storage.stage_commit(record));
    if result.is_err() {
        storage.stage_abort();
    }
    result
}

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
    storage: &mut (impl Storage + ?Sized),
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
    storage: &mut (impl Storage + ?Sized),
    rsa: bool,
    width: usize,
    key: &[u8; crate::ports::key_layout::SIZE],
    metadata: &[u8],
) -> Result<(), StorageError> {
    if width > layout::RSA_LIMB_BYTES {
        return Err(StorageError::Unavailable);
    }
    if !rsa {
        return storage.stage_parts(&[&[KEY_FORMAT_VERSION], &key[..width], metadata]);
    }
    let mut parts: [&[u8]; 8] = [&[]; 8];
    parts[0] = &[KEY_FORMAT_VERSION];
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
