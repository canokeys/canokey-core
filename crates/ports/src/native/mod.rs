// SPDX-License-Identifier: Apache-2.0
//! Shared native crypto imports. Device and storage adapters have outer owners.
mod crypto;
pub use crypto::CryptoBackend;

pub use crate::MemoryBackend;
