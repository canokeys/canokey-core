// SPDX-License-Identifier: Apache-2.0
// Compile the production link facades with fake packet hardware and core calls.
// The applet/fragmentation engines have their own Rust and integration suites.
extern crate self as canokey_rust_core;
extern crate self as canokey_protocol;
#[path = "../../../protocol/src/ctaphid.rs"]
pub mod ctaphid;
#[path = "../../src/runtime/keyboard.rs"]
pub mod keyboard_policy;
pub mod runtime {
    pub use crate::keyboard_policy as keyboard;
}
#[cfg(hid_fixture)]
#[path = "../../../ffi/src/hid_link.rs"]
mod hid_link;
#[cfg(keyboard_fixture)]
#[path = "../../../ffi/src/keyboard.rs"]
mod keyboard;

#[cfg(feature = "usb-webusb")]
mod webusb_link {
    unsafe extern "C" { fn test_web_blocked() -> u8; }
    pub unsafe fn block_competitor() -> bool { unsafe { test_web_blocked() != 0 } }
}

#[cfg(keyboard_fixture)]
#[path = "../../../ffi/src/keyboard_io.rs"]
mod keyboard_io;

#[cfg(hid_fixture)]
#[path = "../../../ffi/src/hid_io.rs"]
mod hid_io;
