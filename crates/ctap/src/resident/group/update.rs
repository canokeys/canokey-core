// SPDX-License-Identifier: Apache-2.0
//! Synchronous CTG1 replacement with explicit file-cache ownership strategies.
use super::{HEADER_BYTES, Header, MEMBERS, Replacement, member_length};
use crate::resident::Entry;

/// The owner lends its existing scratch and admits the group header and new
/// member before entry. No callback may reenter storage during this operation.
/// Buffered owners read peers before acquiring the staging cache lease; streamed
/// owners must support closing each append before reading the published group.
pub trait Backend {
    type Error;
    /// Read all unchanged peers before staging; requires their combined size
    /// in scratch. Otherwise each append must release its handle before read.
    const BUFFER_PEERS: bool;
    /// Validate every existing member before same-length no-op/patch. False
    /// preserves target-only comparison for owners that replace it in full.
    const VALIDATE_PATCH_PEERS: bool;

    fn invalid_record(&self) -> Self::Error;
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Self::Error>;
    fn prepare(&mut self, total_bytes: usize) -> Result<(), Self::Error>;
    fn patch(&mut self, offset: usize, value: &[u8]) -> Result<(), Self::Error>;
    fn remove(&mut self) -> Result<(), Self::Error>;
    fn stage_begin(&mut self) -> Result<(), Self::Error>;
    fn stage_append(&mut self, value: &[u8]) -> Result<(), Self::Error>;
    fn stage_commit(&mut self) -> Result<(), Self::Error>;
    /// Buffered publication calls this after stage_parts or commit failure.
    /// Streamed owners must close handles on every IO return themselves.
    fn stage_abort(&mut self);

    fn stage_parts(&mut self, parts: &[&[u8]]) -> Result<(), Self::Error> {
        self.stage_begin()?;
        for part in parts {
            self.stage_append(part)?;
        }
        Ok(())
    }
}

/// Update one admitted member. Scratch is at least one member for streamed
/// owners or max(one member, all unchanged peers) for buffered owners; its lifetime and erasure
/// stay with the product reservation. Errors never cause automatic retries.
pub fn replace<B: Backend>(
    header: Header,
    member: usize,
    value: &[u8],
    scratch: &mut [u8],
    backend: &mut B,
) -> Result<(), B::Error> {
    update(header, member, value, scratch, backend, true)
}

/// Prepare a complete unpublished replacement, including same-length changes.
/// The caller owns the staged object until commit or abort. Ordinary record
/// reads/writes may release its cache lease but must preserve its bytes. This
/// never patches/removes a published group; registration can finish signing
/// before the single durable publication. The supplied member is admitted by
/// the owner, as for replace. Errors never retry or publish an incomplete group.
pub fn stage<B: Backend>(
    header: Header,
    member: usize,
    value: &[u8],
    scratch: &mut [u8],
    backend: &mut B,
) -> Result<(), B::Error> {
    update(header, member, value, scratch, backend, false)
}

#[inline(never)]
fn update<B: Backend>(
    mut header: Header,
    member: usize,
    value: &[u8],
    scratch: &mut [u8],
    backend: &mut B,
    publish: bool,
) -> Result<(), B::Error> {
    let replacement =
        Replacement::new(&header, member, value.len()).map_err(|_| backend.invalid_record())?;
    if publish && replacement.old_length != 0 && replacement.old_length == value.len() {
        let mut unchanged = false;
        let mut offset = HEADER_BYTES;
        for peer in 0..MEMBERS {
            let length = member_length(&header, peer);
            if length != 0 && (B::VALIDATE_PATCH_PEERS || peer == member) {
                let bytes = scratch
                    .get_mut(..length)
                    .ok_or_else(|| backend.invalid_record())?;
                backend.read(offset, bytes)?;
                if B::VALIDATE_PATCH_PEERS {
                    Entry::decode(bytes).map_err(|_| backend.invalid_record())?;
                }
                if peer == member {
                    unchanged = bytes == value;
                }
            }
            offset += length;
        }
        if unchanged {
            return Ok(());
        }
        backend.prepare(replacement.total_bytes)?;
        return backend.patch(replacement.offset, value);
    }
    if replacement.total_bytes == HEADER_BYTES {
        return if publish {
            backend.remove()
        } else {
            Err(backend.invalid_record())
        };
    }
    let result = if B::BUFFER_PEERS {
        let mut offset = HEADER_BYTES;
        let mut used = 0;
        for peer in 0..MEMBERS {
            let length = member_length(&header, peer);
            if peer != member && length != 0 {
                let bytes = scratch
                    .get_mut(used..used + length)
                    .ok_or_else(|| backend.invalid_record())?;
                backend.read(offset, bytes)?;
                Entry::decode(bytes).map_err(|_| backend.invalid_record())?;
                used += length;
            }
            offset += length;
        }
        let before = replacement.offset - HEADER_BYTES;
        Replacement::set_length(&mut header, member, value.len());
        backend.prepare(replacement.total_bytes)?;
        let result =
            backend.stage_parts(&[&header, &scratch[..before], value, &scratch[before..used]]);
        if result.is_err() {
            backend.stage_abort();
        }
        result
    } else {
        let lengths: [usize; MEMBERS] = core::array::from_fn(|peer| member_length(&header, peer));
        Replacement::set_length(&mut header, member, value.len());
        backend.prepare(replacement.total_bytes)?;
        backend.stage_begin()?;
        backend.stage_append(&header)?;
        let mut offset = HEADER_BYTES;
        for (peer, length) in lengths.into_iter().enumerate() {
            let bytes = scratch
                .get_mut(..length)
                .ok_or_else(|| backend.invalid_record())?;
            if length != 0 {
                backend.read(offset, bytes)?;
                Entry::decode(bytes).map_err(|_| backend.invalid_record())?;
            }
            backend.stage_append(if peer == member { value } else { bytes })?;
            offset += length;
        }
        Ok(())
    };
    result?;
    if !publish {
        return Ok(());
    }
    let result = backend.stage_commit();
    if B::BUFFER_PEERS && result.is_err() {
        backend.stage_abort();
    }
    result
}
