// SPDX-License-Identifier: Apache-2.0
//! Certificate windows borrow product backing only for the synchronous read.
use crate::ports::Certificate;

pub mod auth_data;
pub mod credential;
pub mod encoding;
pub mod extensions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    Exact,
    /// U2F ISO registration may advance by a positive short read. The outer
    /// response lease rejects zero progress; this layer preserves its count.
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError<E> {
    Source(E),
    Length,
}

/// The product validates the window against its prepared response metadata.
/// This function preserves source errors and admits only a count that fits the
/// borrowed destination. Failed or partial writes remain caller-owned; the
/// outer response owner must erase unpublished bytes before reuse/publication.
pub fn certificate<S: Certificate>(
    source: &mut S,
    offset: u32,
    output: &mut [u8],
    mode: ReadMode,
) -> Result<usize, ReadError<S::Error>> {
    let count = source
        .read(offset, output, mode)
        .map_err(ReadError::Source)?;
    if count > output.len() || (mode == ReadMode::Exact && count != output.len()) {
        Err(ReadError::Length)
    } else {
        Ok(count)
    }
}
