// SPDX-License-Identifier: Apache-2.0
// Compile the production link facades with fake packet hardware and core calls.
// The applet/fragmentation engines have their own Rust and integration suites.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[allow(dead_code)]
#[path = "../../crates/ffi/src/sys.rs"]
mod sys;
#[path = "../../crates/protocol/src/ctaphid.rs"]
pub mod ctaphid;
#[path = "../../crates/protocol/src/usb.rs"]
pub mod usb;
#[cfg(hid_fixture)]
#[path = "../../crates/ffi/src/transport/hid/link.rs"]
mod hid_link;

#[cfg(feature = "usb-webusb")]
mod webusb_link {
    unsafe extern "C" {
        fn test_web_blocked() -> u8;
    }
    pub unsafe fn try_preempt(_: bool) -> bool {
        false
    }
    pub unsafe fn block_competitor() -> bool {
        unsafe { test_web_blocked() != 0 }
    }
}

#[cfg(hid_fixture)]
#[path = "../../crates/ffi/src/transport/hid/io.rs"]
mod hid_io;

#[path = "../../crates/ffi/src/transport/lock.rs"]
mod usb_lock;

#[cfg(hid_fixture)]
use hid_io as io;
#[cfg(hid_fixture)]
mod command {
    unsafe extern "C" {
        pub fn ck_hid_reset();
        pub fn ck_hid_poll(input: *const [u8; 64], received: u32, now: u32, output: *mut [u8; 64]) -> u8;
    }
}

mod transport {
    pub(crate) use crate::usb_lock::usb_locked;
    pub(crate) mod usb_io {
        unsafe extern "C" {
            pub fn ck_usb_configured() -> u8;
            pub fn ck_usb_tx_idle(endpoint: u8) -> u8;
            pub fn ck_usb_submit(endpoint: u8, bytes: *const u8, length: u16, zlp: u8) -> i32;
            pub fn ck_usb_receive(endpoint: u8);
        }
    }
    #[cfg(feature = "usb-webusb")]
    pub(crate) use crate::webusb_link as webusb;
}
