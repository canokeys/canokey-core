// SPDX-License-Identifier: Apache-2.0
// Actual production USB runtime and IRQ facade, without applet mocks inside it.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[path = "../../crates/protocol/src/apdu.rs"]
pub mod apdu;
#[path = "../../crates/protocol/src/ccid.rs"]
pub mod ccid;
#[path = "../../crates/protocol/src/ctaphid.rs"]
pub mod ctaphid;
#[path = "../../crates/protocol/src/response.rs"]
pub mod response;
#[path = "../../crates/protocol/src/usb.rs"]
mod usb_wire;
pub mod usb {
    #[cfg(feature = "usb-webusb")]
    pub(crate) use crate::usb_ffi::web_admission;
    pub use crate::usb_wire::*;
}
#[path = "../../crates/core/src/runtime/usb/mod.rs"]
pub mod usb_runtime;
#[path = "../../crates/core/src/runtime/webusb.rs"]
pub mod webusb_runtime;
pub mod runtime {
    pub use crate::usb_runtime as usb;
    pub use crate::webusb_runtime as webusb;
}
#[path = "../../crates/ffi/src/transport/usb.rs"]
mod usb_ffi;
#[cfg(feature = "usb-webusb")]
#[path = "../../crates/ffi/src/transport/webusb.rs"]
mod webusb_link;

#[cfg(feature = "usb-webusb")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_web_blocked() -> u8 {
    unsafe { webusb_link::block_competitor() as u8 }
}

#[cfg(feature = "usb-keyboard")]
#[path = "../../crates/ffi/src/transport/keyboard/io.rs"]
mod keyboard_io;

#[cfg(feature = "usb-hid")]
#[path = "../../crates/ffi/src/transport/hid/io.rs"]
mod hid_io;

#[path = "../../crates/ffi/src/transport/ccid/io.rs"]
mod ccid_io;

#[cfg(feature = "usb-webusb")]
mod entrypoints {
    unsafe extern "C" {
        fn test_core_preemptable() -> u8;
        pub fn ck_core_reset();
        pub fn ck_core_exchange(
            owner: u8,
            input: *const u8,
            length: usize,
            output: *mut u8,
            capacity: usize,
        ) -> i32;
    }
    pub unsafe fn can_preempt() -> bool {
        unsafe { test_core_preemptable() != 0 }
    }
}
#[cfg(feature = "usb-webusb")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_web_preempt(requested: u8) -> u8 {
    unsafe { webusb_link::try_preempt(requested != 0) as u8 }
}

// This fixture isolates USB/controller behavior; usb-sessions links the actual
// CCID/Core progress path and verifies presence polling during HID execution.
#[cfg(feature = "usb-hid")]
mod ccid_policy {
    pub unsafe fn presence_progress() {
        unreachable!("HID execution belongs in usb-sessions")
    }
}

#[path = "../../crates/ffi/src/transport/owners.rs"]
mod owners;
#[path = "../../crates/ffi/src/transport/lock.rs"]
mod usb_lock;

mod transport {
    pub(crate) use crate::owners;
    pub(crate) use crate::usb_lock::usb_locked;
    pub(crate) mod ccid {
        unsafe extern "C" {
            pub fn ck_ccid_response_buffer() -> *mut u8;
            pub fn ck_ccid_idle() -> u8;
        }
        pub(crate) use crate::ccid_io as io;
        #[cfg(feature = "usb-hid")]
        pub(crate) use crate::ccid_policy::presence_progress;
    }
    pub(crate) use crate::usb;
    #[cfg(feature = "usb-webusb")]
    pub(crate) use crate::webusb_link as webusb;
    #[cfg(any(hid_fixture, feature = "usb-hid"))]
    pub(crate) mod hid {
        pub(crate) use crate::hid_io as io;
        pub(crate) mod link {
            unsafe extern "C" {
                pub fn ck_hid_busy() -> u8;
            }
        }
    }
    #[cfg(any(keyboard_fixture, feature = "usb-keyboard"))]
    pub(crate) mod keyboard {
        pub(crate) use crate::keyboard_io as io;
    }
}
#[cfg(feature = "usb-webusb")]
mod abi {
    pub(crate) use crate::entrypoints as core;
}
