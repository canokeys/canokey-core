// SPDX-License-Identifier: Apache-2.0
//! Platform contracts and backend-independent binding policy.
#![no_std]
mod binding;
pub mod contracts;
mod memory;
#[cfg(any(feature = "oath", feature = "piv"))]
pub use binding::copy_to_stage;
pub use binding::{BackendTypes, Backends, DynamicBackends, Platform, default_memory};
pub use contracts::*;
pub use memory::MemoryBackend;
