// SPDX-License-Identifier: Apache-2.0
// Production boot/loop FFI; the harness supplies board and Core boundaries.
extern crate self as canokey_rust_core;
#[allow(dead_code)]
#[path = "../../crates/ffi/src/sys.rs"]
mod sys;
pub mod runtime {
    pub mod config {
        pub const INITIALIZED: u32 = 1;
        pub const NFC: u32 = 2;
        pub const LED: u32 = 4;
        pub const WEBUSB: u32 = 16;
        pub const DEFAULT_FLAGS: u32 = 0x1f9e;
    }
}
mod nfc {
    unsafe extern "C" {
        pub fn is_nfc() -> u8;
        pub fn ck_nfc_set_mode(active: u8);
        pub fn ck_nfc_configure() -> i32;
        pub fn ck_nfc_silence() -> i32;
        pub fn nfc_init();
        pub fn nfc_loop();
    }
}
#[path = "../../crates/ffi/src/runtime/device.rs"]
mod facade;

#[path = "../../crates/ffi/src/runtime/timer.rs"]
mod timer;

#[path = "../../crates/ffi/src/transport/lock.rs"]
mod usb_lock;

mod abi {
    pub(crate) mod core {
        unsafe extern "C" {
            pub fn ck_core_boot_flags(out: *mut u32) -> i32;
            pub fn ck_core_install() -> i32;
            pub fn ck_core_mark_initialized() -> i32;
        }
    }
}

mod transport {
    pub(crate) use crate::nfc;
    pub(crate) use crate::usb_lock::usb_locked;
    pub(crate) mod usb {
        unsafe extern "C" {
            pub fn ck_usb_set_landing(enabled: u8);
            pub fn ck_transport_progress() -> u8;
            pub fn usb_device_init();
        }
    }
    pub(crate) mod ccid {
        unsafe extern "C" {
            pub fn CCID_Loop();
        }
    }
    pub(crate) mod hid {
        pub(crate) mod link {
            unsafe extern "C" {
                pub fn CTAPHID_Loop(wait: u8) -> u8;
            }
        }
    }
    pub(crate) mod keyboard {
        unsafe extern "C" {
            pub fn ck_keyboard_loop();
        }
    }
    pub(crate) mod webusb {
        unsafe extern "C" {
            pub fn WebUSB_Loop();
        }
    }
}
