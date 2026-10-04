// SPDX-License-Identifier: Apache-2.0
// Compile the production link facades with fake packet hardware and core calls.
// The applet/fragmentation engines have their own Rust and integration suites.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[path = "../../crates/protocol/src/ctaphid.rs"]
pub mod ctaphid;
#[path = "../../crates/core/src/runtime/keyboard.rs"]
pub mod keyboard_policy;
#[path = "../../crates/protocol/src/usb.rs"]
pub mod usb;
pub mod runtime {
    pub use crate::keyboard_policy as keyboard;
}
#[cfg(hid_fixture)]
#[path = "../../crates/ffi/src/transport/hid/link.rs"]
mod hid_link;
#[cfg(keyboard_fixture)]
#[path = "../../crates/ffi/src/transport/keyboard/mod.rs"]
mod keyboard;

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

mod transport {
    pub(crate) use crate::usb_lock::usb_locked;
    #[cfg(feature = "usb-webusb")]
    pub(crate) use crate::webusb_link as webusb;
}
