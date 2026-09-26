// SPDX-License-Identifier: Apache-2.0
// Actual production USB runtime and IRQ facade, without applet mocks inside it.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[path = "../../../protocol/src/usb.rs"]
pub mod usb;
#[path = "../../src/runtime/usb/mod.rs"]
pub mod usb_runtime;
pub mod runtime { pub use crate::usb_runtime as usb; }
#[path = "../../../ffi/src/usb.rs"]
mod usb_ffi;
