// SPDX-License-Identifier: Apache-2.0
#![no_std]
#[cfg(test)]
extern crate std;
#[cfg(test)]
#[allow(dead_code)] // Reduced feature profiles may contain no transport scenario.
static TRANSPORT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
// C entrypoints use the same serialized, lazy BSS initialization
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
mod abi;
pub mod composition;
#[cfg(any(feature = "native-composition", test))]
mod platform;
mod runtime;
mod sys;
mod transport;
#[cfg(feature = "native-composition")]
pub use abi::core::{ck_core_exchange, ck_core_install, ck_core_reset, ck_core_slot_power};
#[cfg(all(feature = "ctap", feature = "native-composition"))]
pub use platform::ck_core_presence_sample;
#[cfg(all(feature = "usb-ccid", feature = "native-composition"))]
pub use transport::ccid::CCID_Loop;
#[cfg(all(feature = "ctap", feature = "native-composition"))]
pub use transport::hid::command::{ck_hid_poll, ck_hid_reset};
#[cfg(all(feature = "usb-hid", feature = "native-composition"))]
pub use transport::hid::link::CTAPHID_Loop;
#[cfg(feature = "usb-hid")]
pub use transport::hid::{
    io::{ck_hid_packet_reset, out_event, rx_can_accept},
    link::{ck_hid_executing, ck_hid_progress},
};
#[cfg(all(feature = "usb-keyboard", feature = "native-composition"))]
pub use transport::keyboard::ck_keyboard_loop;
#[cfg(feature = "nfc")]
pub use transport::nfc::{ck_nfc_configure, ck_nfc_set_mode, ck_nfc_silence};
#[cfg(all(feature = "nfc", feature = "native-composition"))]
pub use transport::nfc::{nfc_init, nfc_loop};
#[cfg(feature = "usb-device")]
pub use transport::usb::usb_device_init;
#[cfg(all(feature = "usb-webusb", feature = "native-composition"))]
pub use transport::webusb::WebUSB_Loop;
// The FFI crate is the C-facing facade; re-export the core's public port types
// so platform adapters and generated bindings share one type namespace.
pub use canokey_rust_core::{Core, Platform, Reply, ports};
#[cfg(all(feature = "host-runtime", target_os = "none"))]
compile_error!("host-runtime must not be enabled in firmware");
#[cfg(all(feature = "host-runtime", not(test)))]
unsafe extern "C" {
    fn abort() -> !;
}
#[cfg(all(feature = "host-runtime", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
#[cfg(all(feature = "host-runtime", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() -> ! {
    // The linker may still request this unwinding symbol even though firmware
    // uses panic=abort; route it through the same terminal abort path.
    unsafe { abort() }
}
