// SPDX-License-Identifier: Apache-2.0
//! Shared crypto imports and temporary device adapters.
//! Storage adapters belong to the outer platform or compatibility composition.
mod crypto;
pub use crypto::CryptoBackend;

#[cfg(feature = "native-backend")]
mod device;
pub use crate::MemoryBackend;
#[cfg(all(feature = "native-backend", feature = "ctap"))]
pub use device::presence_sample;
#[cfg(feature = "native-backend")]
pub use device::{DeviceBackend, DeviceRuntime};
