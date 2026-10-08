// SPDX-License-Identifier: Apache-2.0
//! One implementation serves direct firmware calls and trait-based host tests.
//! Only this adapter layer crosses the native ABI.
mod crypto;
mod storage;
pub use crypto::CryptoBackend;
pub use storage::StorageBackend;

mod device;
pub use crate::MemoryBackend;
pub use device::DeviceBackend;
#[cfg(feature = "ctap")]
pub use device::ck_core_presence_sample;
