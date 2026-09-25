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
