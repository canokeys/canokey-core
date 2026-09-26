// SPDX-License-Identifier: Apache-2.0
#![no_std]
// Both C entrypoint families use the same serialized, lazy BSS initialization
// pattern. Keeping it in one macro prevents the READY flag and constructor
// safety contract from drifting between CORE and HID state.
#[macro_export]
macro_rules! lazy_state {
    ($state:ident, $ready:ident, $ty:ty, $init:expr, $initializer:ident, $getter:ident) => {
        static mut $state: core::mem::MaybeUninit<$ty> = core::mem::MaybeUninit::uninit();
        static mut $ready: bool = false;

        #[cold]
        #[inline(never)]
        unsafe fn $initializer(state: *mut $ty) {
            unsafe { state.write($init) }
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
mod entrypoints;
mod platform;
// The FFI crate is the C-facing facade; re-export the core's public port types
// so platform adapters and generated bindings share one type namespace.
pub use canokey_rust_core::*;
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

#[cfg(feature = "ctap")]
mod ctaphid;

#[cfg(feature = "usb-ccid")]
mod ccid;

#[cfg(feature = "usb-hid")]
mod hid_link;
#[cfg(feature = "usb-keyboard")]
mod keyboard;
#[cfg(feature = "usb-device")]
mod usb;

#[cfg(feature = "usb-webusb")]
mod webusb_link;
