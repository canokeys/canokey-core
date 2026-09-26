// SPDX-License-Identifier: Apache-2.0
// Production boot/loop FFI; the harness supplies board and Core boundaries.
extern crate self as canokey_rust_core;
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
#[path = "../../../ffi/src/device.rs"]
mod facade;

#[path = "../../../ffi/src/timer.rs"]
mod timer;
