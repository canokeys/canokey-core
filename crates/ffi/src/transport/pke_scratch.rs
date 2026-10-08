// SPDX-License-Identifier: Apache-2.0
// Must match PKE_BUFFER_OWNER_CTAP in native/support/include/pke.h.
const PKE_OWNER_CTAP: u8 = 3;
use crate::composition::{Provider, Staging};
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
    pub fn acquire<P: Provider>(&mut self) -> bool {
        if !P::Staging::acquire(PKE_OWNER_CTAP) {
            return false;
        }
        self.active = true;
        true
    }
    pub fn close<P: Provider>(&mut self) {
        if self.active {
            close_acquired::<P>();
            self.active = false;
        }
    }
}
pub fn close_acquired<P: Provider>() {
    // Failed cleanup must halt before another request can reuse secrets.
    assert!(P::Staging::clear());
    assert!(P::Staging::release(PKE_OWNER_CTAP));
}
#[cfg(feature = "usb-ccid")]
#[inline(always)]
pub fn acquire<P: Provider>() -> bool {
    P::Staging::acquire(PKE_OWNER_CTAP)
}
pub fn capacity<P: Provider>() -> usize {
    P::Staging::capacity()
}
#[inline(always)]
pub fn read<P: Provider>(offset: usize, out: &mut [u8]) -> bool {
    P::Staging::read(offset, out)
}
#[inline(always)]
pub fn write<P: Provider>(offset: usize, bytes: &[u8]) -> bool {
    P::Staging::write(offset, bytes)
}
