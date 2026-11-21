// SPDX-License-Identifier: Apache-2.0
use crate::composition::{Provider, Staging};
use canokey_ports::PKE_LEASE_CTAP;
use canokey_rust_core::runtime::owners::{
    OWNER_CCID, OWNER_CTAP, OWNER_INVALID, OWNER_NFC, OWNER_WEBUSB,
};

const _: () = assert!(!matches!(
    PKE_LEASE_CTAP,
    OWNER_INVALID | OWNER_CCID | OWNER_CTAP | OWNER_WEBUSB | OWNER_NFC
));
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
        if !P::Staging::acquire(PKE_LEASE_CTAP) {
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
    assert!(P::Staging::release(PKE_LEASE_CTAP));
}
#[cfg(all(feature = "nfc", not(test)))]
#[inline(always)]
pub fn acquire<P: Provider>() -> bool {
    P::Staging::acquire(PKE_LEASE_CTAP)
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
