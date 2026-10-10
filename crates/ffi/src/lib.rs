// SPDX-License-Identifier: Apache-2.0
#![no_std]
#[cfg(test)]
extern crate std;
#[cfg(test)]
#[allow(dead_code)] // Reduced feature profiles may contain no transport scenario.
static TRANSPORT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
// Runtime entrypoints use the same serialized, lazy BSS initialization
// pattern. Keeping it in one macro prevents the READY flag and constructor
// safety contract from drifting between CORE, CCID and HID state.
#[macro_export]
macro_rules! lazy_state {
    ($state:ident, $ready:ident, $ty:ty, $init:expr, $initializer:ident, $getter:ident) => {
        static mut $state: core::mem::MaybeUninit<$ty> = core::mem::MaybeUninit::uninit();
        static mut $ready: bool = false;

        #[cold]
        #[inline(never)]
        unsafe fn $initializer(state: *mut $ty) {
            let initial = $init;
            unsafe { state.write(initial) }
        }

        unsafe fn $getter() -> &'static mut $ty {
            unsafe {
                let state = core::ptr::addr_of_mut!($state).cast::<$ty>();
                if !$ready {
                    $initializer(state);
                    $ready = true;
                }
                &mut *state
            }
        }
    };
}
pub mod composition;
#[cfg(any(feature = "native-platform", test))]
mod platform;
#[cfg(feature = "native-platform")]
pub use platform::Native;
mod runtime;
mod sys;
mod transport;
#[cfg(feature = "usb-hid")]
pub use transport::hid::{
    io::{ck_hid_packet_reset, out_event, rx_can_accept},
    link::{ck_hid_executing, ck_hid_progress},
};
#[cfg(feature = "nfc")]
pub use transport::nfc::{ck_nfc_configure, ck_nfc_set_mode, ck_nfc_silence};
// Platform adapters and generated product bindings share one port namespace.
pub use canokey_rust_core::{Core, Platform, Reply, ports};
