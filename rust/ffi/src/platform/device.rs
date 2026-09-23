// SPDX-License-Identifier: Apache-2.0
//! Device callbacks and volatile secret erasure adapter.
use canokey_rust_core::ports::{Device, Memory};

pub(super) struct DeviceBackend;
pub(super) struct MemoryBackend;

#[cfg(any(
    feature = "admin",
    feature = "pass",
    feature = "oath",
    feature = "openpgp",
    feature = "piv"
))]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
}
#[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
unsafe extern "C" {
    fn ck_platform_serial(out: *mut u8);
}
impl Device for DeviceBackend {
    fn serial(&mut self, out: &mut [u8; 4]) {
        #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
        {
            unsafe { ck_platform_serial(out.as_mut_ptr()) }
        }
        #[cfg(not(any(feature = "oath", feature = "openpgp", feature = "piv")))]
        {
            let _ = out;
        }
    }
    fn now(&mut self) -> u32 {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_now() }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            0
        }
    }
    fn touched(&mut self) -> bool {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_touched() != 0 }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            false
        }
    }
    fn progress(&mut self) -> bool {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_progress() != 0 }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            false
        }
    }
    fn led(&mut self, on: bool) {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_led(u8::from(on)) }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = on;
        }
    }
}
impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}
