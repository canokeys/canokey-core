// SPDX-License-Identifier: Apache-2.0
//! Platform contracts and the native C adapter boundary. Firmware may statically
//! bind storage/crypto while host compositions keep injectable trait objects.
#![no_std]
mod crypto;
mod device;
mod storage;
pub use crypto::*;
pub use device::*;
pub use storage::*;

pub mod native;

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type StoragePort<'a> = native::StorageBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type StoragePort<'a> = dyn Storage + 'a;
#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type CryptoPort<'a> = native::CryptoBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type CryptoPort<'a> = dyn Crypto + 'a;

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type DevicePort<'a> = native::DeviceBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type DevicePort<'a> = dyn Device + 'a;
#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub type MemoryPort<'a> = native::MemoryBackend;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub type MemoryPort<'a> = dyn Memory + 'a;

/// Disjoint capabilities assembled at the boundary. Borrow individual fields;
/// never wrap the entire platform in an interior-mutable shared handle.
pub struct Platform<'a> {
    pub storage: &'a mut StoragePort<'a>,
    pub crypto: &'a mut CryptoPort<'a>,
    pub device: &'a mut DevicePort<'a>,
    pub memory: &'a MemoryPort<'a>,
}
