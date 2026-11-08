// SPDX-License-Identifier: Apache-2.0
//! RP deduplication with caller-owned payload and bounded hash/bitmap scratch.
use super::RP_HASH_BYTES;

const SLOTS_PER_BYTE: usize = 8;
const SLOT_BIT: u8 = 0x01;

pub const fn bitmap_bytes(capacity: u8) -> usize {
    (capacity as usize).div_ceil(SLOTS_PER_BYTE)
}

fn marked(bitmap: &[u8], index: u8) -> bool {
    bitmap[usize::from(index) / SLOTS_PER_BYTE]
        & (SLOT_BIT << (usize::from(index) % SLOTS_PER_BYTE))
        != 0x00
}
fn mark(bitmap: &mut [u8], index: u8) {
    bitmap[usize::from(index) / SLOTS_PER_BYTE] |=
        SLOT_BIT << (usize::from(index) % SLOTS_PER_BYTE);
}

/// Reads validate according to the product's storage contract and lend only the
/// RP hash. The payload remains in the reader's existing buffer. A batch boundary
/// ends any metadata cache lease; the next pass must start with a fresh cache.
pub trait Reader {
    type Error;
    fn begin_pass(&mut self) {}
    fn read(&mut self, index: u8) -> Result<Option<&[u8; RP_HASH_BYTES]>, Self::Error>;
}

/// Build a representative bitmap in ascending slot order, scanning in bounded
/// batches of complete hashes. Scratch is caller-owned; a nonempty hash window
/// guarantees progress even when every credential belongs to a different RP.
/// `visited` and `representatives` must initially be empty and cover capacity.
/// Each hash loan ends before the next read or pass. No storage writes are issued.
pub fn collect<R: Reader>(
    capacity: u8,
    visited: &mut [u8],
    representatives: &mut [u8],
    hashes: &mut [[u8; RP_HASH_BYTES]],
    reader: &mut R,
) -> Result<u8, R::Error> {
    assert!(visited.len() >= bitmap_bytes(capacity));
    assert!(representatives.len() >= bitmap_bytes(capacity));
    assert!(!hashes.is_empty());
    let mut total = 0;
    loop {
        let mut count = 0;
        let mut pending = false;
        reader.begin_pass();
        for index in 0..capacity {
            if marked(visited, index) {
                continue;
            }
            let Some(hash) = reader.read(index)? else {
                mark(visited, index);
                continue;
            };
            if !hashes[..count].contains(hash) {
                if count == hashes.len() {
                    pending = true;
                    continue;
                }
                hashes[count] = *hash;
                count += 1;
                total += 1;
                mark(representatives, index);
            }
            mark(visited, index);
        }
        if !pending {
            return Ok(total);
        }
    }
}

/// Incremental grouping for products without a hash window. Find the first
/// unvisited occupied slot, mark its later duplicates, then reload that slot so
/// the response can borrow the original payload. Empty slots remain unmarked,
/// preserving read/error order across continuation calls. Partial marks survive
/// an error; the owning session must discard its cursor on failure.
pub fn next_group<R: Reader>(
    capacity: u8,
    visited: &mut [u8],
    reader: &mut R,
) -> Result<bool, R::Error> {
    assert!(visited.len() >= bitmap_bytes(capacity));
    for index in 0..capacity {
        if marked(visited, index) {
            continue;
        }
        let Some(hash) = reader.read(index)?.copied() else {
            continue;
        };
        mark(visited, index);
        for candidate in index + 1..capacity {
            if marked(visited, candidate) {
                continue;
            }
            if reader.read(candidate)?.is_some_and(|other| *other == hash) {
                mark(visited, candidate);
            }
        }
        reader.read(index)?;
        return Ok(true);
    }
    Ok(false)
}

/// Representative selection borrows the loaded payload through the caller.
/// Advance the cursor only after that read succeeds, before encoding/crypto.
pub fn next_representative<T, E>(
    capacity: u8,
    representatives: &[u8],
    next: &mut u8,
    mut read: impl FnMut(u8) -> Result<T, E>,
) -> Result<Option<(u8, T)>, E> {
    assert!(representatives.len() >= bitmap_bytes(capacity));
    for index in *next..capacity {
        if marked(representatives, index) {
            let value = read(index)?;
            *next = index + 1;
            return Ok(Some((index, value)));
        }
    }
    Ok(None)
}
