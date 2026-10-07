// SPDX-License-Identifier: Apache-2.0
//! Portable volatile erasure shared by firmware, host and compatibility APIs.
use crate::Memory;

pub struct MemoryBackend;

impl MemoryBackend {
    #[inline(never)]
    pub fn wipe(&self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        MemoryBackend::wipe(self, bytes)
    }
}
