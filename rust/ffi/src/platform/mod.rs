// SPDX-License-Identifier: Apache-2.0
//! C platform adapters split by capability. The safe core sees only typed ports.
mod crypto;
mod device;
mod storage;

use canokey_rust_core::ports::Platform;
use crypto::CryptoBackend;
use device::{DeviceBackend, MemoryBackend};
use storage::StorageBackend;

pub(crate) fn with_platform<T>(run: impl FnOnce(&mut Platform<'_>) -> T) -> T {
    run(&mut Platform {
        storage: &mut StorageBackend,
        crypto: &mut CryptoBackend,
        device: &mut DeviceBackend,
        memory: &MemoryBackend,
    })
}
