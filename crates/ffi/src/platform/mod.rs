// SPDX-License-Identifier: Apache-2.0
//! C platform adapters split by capability. The safe core sees only typed ports.

use canokey_ports::native::{CryptoBackend, DeviceBackend, MemoryBackend, StorageBackend};
use canokey_ports::{BackendTypes, CryptoPort, DevicePort, MemoryPort, StoragePort};
use canokey_rust_core::ports::Platform;

pub(crate) type BoundPlatform<'a> =
    Platform<'a, BackendTypes<StoragePort<'a>, CryptoPort<'a>, DevicePort<'a>, MemoryPort<'a>>>;

pub(crate) fn with_platform<T>(run: impl FnOnce(&mut BoundPlatform<'_>) -> T) -> T {
    // SAFETY: callers are the serialized C entrypoints or their main-loop
    // continuation. The closure cannot let any of these borrows escape.
    let (mut storage, mut crypto, mut device) = unsafe {
        (
            StorageBackend::new(),
            CryptoBackend::new(),
            DeviceBackend::new(),
        )
    };
    run(&mut Platform::new(
        &mut storage,
        &mut crypto,
        &mut device,
        &MemoryBackend,
    ))
}
