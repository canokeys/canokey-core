// SPDX-License-Identifier: Apache-2.0
// Must match PKE_BUFFER_OWNER_CTAP in native/include/pke.h.
const PKE_OWNER_CTAP: u8 = 3;
use crate::sys::pke_buffer_acquire;
use crate::sys::pke_buffer_clear;
use crate::sys::pke_buffer_read;
use crate::sys::pke_buffer_release;
use crate::sys::pke_buffer_size;
use crate::sys::pke_buffer_write;
// Serialized transports retain bookkeeping across polls, never hardware slices.
// Cleanup is explicit: a temporary platform adapter must not release the lease.
pub struct PkeLease {
    active: bool,
}
impl PkeLease {
    pub const fn new() -> Self {
        Self { active: false }
    }
    #[inline(always)]
    pub fn acquire(&mut self) -> bool {
        if unsafe { pke_buffer_acquire(PKE_OWNER_CTAP) } != 0 {
            return false;
        }
        self.active = true;
        true
    }
    pub fn close(&mut self) {
        if self.active {
            close_acquired();
            self.active = false;
        }
    }
}
pub fn close_acquired() {
    // Failed cleanup must halt before another request can reuse secrets.
    unsafe {
        assert_eq!(pke_buffer_clear(), 0);
        assert_eq!(pke_buffer_release(PKE_OWNER_CTAP), 0);
    }
}
#[cfg(feature = "usb-ccid")]
#[inline(always)]
pub fn acquire() -> bool {
    unsafe { pke_buffer_acquire(PKE_OWNER_CTAP) == 0 }
}
pub fn capacity() -> usize {
    unsafe { pke_buffer_size() }
}
#[inline(always)]
pub fn read(offset: usize, out: &mut [u8]) -> bool {
    unsafe { pke_buffer_read(offset, out.as_mut_ptr(), out.len()) == 0 }
}
#[inline(always)]
pub fn write(offset: usize, bytes: &[u8]) -> bool {
    unsafe { pke_buffer_write(offset, bytes.as_ptr(), bytes.len()) == 0 }
}
