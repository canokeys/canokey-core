// SPDX-License-Identifier: Apache-2.0
mod crypto;
mod device;
mod storage;
pub use crypto::*;
pub use device::*;
pub use storage::*;

/// Disjoint capabilities assembled at the boundary. Borrow individual fields;
/// never wrap the entire platform in an interior-mutable shared handle.
pub struct Platform<'a> {
    pub storage: &'a mut dyn Storage,
    pub crypto: &'a mut dyn Crypto,
    pub device: &'a mut dyn Device,
    pub memory: &'a dyn Memory,
}
