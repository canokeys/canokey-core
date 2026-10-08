// SPDX-License-Identifier: Apache-2.0
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_ports::Storage as _;

pub fn load_or_else<const N: usize, T, E, B: crate::ports::Backends>(
    p: &mut Platform<'_, B>,
    record: Record,
    buf: &mut [u8; N],
    validate: impl FnOnce(&mut [u8; N], usize) -> Result<T, E>,
    init: impl FnOnce(&mut [u8; N], &mut Platform<'_, B>) -> Result<T, E>,
    io: impl FnOnce(StorageError) -> E,
) -> Result<T, E> {
    match p.storage.load(record, buf) {
        Ok(n) => validate(buf, n),
        Err(StorageError::Missing) => init(buf, p),
        Err(error) => Err(io(error)),
    }
}
