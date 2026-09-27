// SPDX-License-Identifier: Apache-2.0
//! Static firmware binding and injectable host binding share the same contracts.

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type StoragePort<'a> = crate::native::StorageBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type StoragePort<'a> = dyn crate::Storage + 'a;
#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type CryptoPort<'a> = crate::native::CryptoBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type CryptoPort<'a> = dyn crate::Crypto + 'a;

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type DevicePort<'a> = crate::native::DeviceBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type DevicePort<'a> = dyn crate::Device + 'a;
#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type MemoryPort<'a> = crate::native::MemoryBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type MemoryPort<'a> = dyn crate::Memory + 'a;

/// Disjoint capabilities assembled at the boundary. Borrow individual fields;
/// never wrap the entire platform in an interior-mutable shared handle.
pub struct Platform<'a> {
    pub storage: &'a mut StoragePort<'a>,
    pub crypto: &'a mut CryptoPort<'a>,
    pub device: &'a mut DevicePort<'a>,
    pub memory: &'a MemoryPort<'a>,
}

/// Copy a bounded window into an active staging transaction, wiping temporary data.
#[cfg(any(feature = "oath", feature = "piv"))]
pub fn copy_to_stage(
    storage: &mut crate::StoragePort<'_>,
    memory: &crate::MemoryPort<'_>,
    record: crate::Record,
    mut offset: u32,
    mut length: u32,
) -> Result<(), crate::StorageError> {
    let mut buffer = [0; 128];
    let result = (|| {
        while length != 0 {
            let n = length.min(buffer.len() as u32) as usize;
            storage.read_at(record, offset, &mut buffer[..n])?;
            storage.stage_append(&buffer[..n])?;
            offset += n as u32;
            length -= n as u32;
        }
        Ok(())
    })();
    memory.wipe(&mut buffer);
    result
}

/// Default wipe/staging capability for compatibility entrypoints without Platform.
/// Construction is safe; all access remains bounded by the Memory contract.
pub fn default_memory() -> crate::native::MemoryBackend {
    crate::native::MemoryBackend
}
