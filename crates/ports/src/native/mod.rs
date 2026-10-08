// SPDX-License-Identifier: Apache-2.0
//! One implementation serves direct firmware calls and trait-based host tests.
//! Only this adapter layer crosses the native ABI.
mod crypto;
#[cfg(feature = "native-backend")]
mod storage;
pub use crypto::CryptoBackend;
#[cfg(feature = "native-backend")]
pub use storage::StorageBackend;

#[cfg(feature = "native-backend")]
mod device;
pub use crate::MemoryBackend;
#[cfg(feature = "native-backend")]
pub use device::DeviceBackend;
#[cfg(all(feature = "native-backend", feature = "ctap"))]
pub use device::ck_core_presence_sample;
