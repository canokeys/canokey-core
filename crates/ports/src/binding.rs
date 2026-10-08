// SPDX-License-Identifier: Apache-2.0
//! Static firmware binding and injectable host binding share the same contracts.
//! `static-backend` alone selects concrete native adapters. `dynamic-backend`
//! selects trait objects and takes precedence when both features are enabled;
//! neither feature also selects trait objects.

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
pub type MemoryPort<'a> = crate::MemoryBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type MemoryPort<'a> = dyn crate::Memory + 'a;

/// Disjoint capabilities assembled at the boundary. Borrow individual fields;
/// never wrap the entire platform in an interior-mutable shared handle.
pub struct Platform<'a, B: Backends = DynamicBackends<'a>> {
    pub storage: &'a mut B::Storage,
    pub crypto: &'a mut B::Crypto,
    pub device: &'a mut B::Device,
    pub memory: &'a B::Memory,
}

/// A backend family keeps capability types consistent across runtime routing.
/// The family carries types only; Platform stores the four disjoint borrows.
pub trait Backends {
    type Storage: crate::Storage + ?Sized;
    type Crypto: crate::Crypto + ?Sized;
    type Device: crate::Device + ?Sized;
    type Memory: crate::Memory + ?Sized;
}

pub struct BackendTypes<S: ?Sized, C: ?Sized, D: ?Sized, M: ?Sized>(
    core::marker::PhantomData<(*const S, *const C, *const D, *const M)>,
);

impl<S, C, D, M> Backends for BackendTypes<S, C, D, M>
where
    S: crate::Storage + ?Sized,
    C: crate::Crypto + ?Sized,
    D: crate::Device + ?Sized,
    M: crate::Memory + ?Sized,
{
    type Storage = S;
    type Crypto = C;
    type Device = D;
    type Memory = M;
}

pub type DynamicBackends<'a> = BackendTypes<
    dyn crate::Storage + 'a,
    dyn crate::Crypto + 'a,
    dyn crate::Device + 'a,
    dyn crate::Memory + 'a,
>;

impl<'a, S, C, D, M> Platform<'a, BackendTypes<S, C, D, M>>
where
    S: crate::Storage + ?Sized,
    C: crate::Crypto + ?Sized,
    D: crate::Device + ?Sized,
    M: crate::Memory + ?Sized,
{
    pub fn new(storage: &'a mut S, crypto: &'a mut C, device: &'a mut D, memory: &'a M) -> Self {
        Self {
            storage,
            crypto,
            device,
            memory,
        }
    }
}

/// Copy a bounded window into an active staging transaction, wiping temporary data.
#[cfg(any(feature = "oath", feature = "piv"))]
pub fn copy_to_stage(
    storage: &mut (impl crate::Storage + ?Sized),
    memory: &(impl crate::Memory + ?Sized),
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
pub fn default_memory() -> crate::MemoryBackend {
    crate::MemoryBackend
}
