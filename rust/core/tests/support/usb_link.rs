// SPDX-License-Identifier: Apache-2.0
// Actual production USB runtime and IRQ facade, without applet mocks inside it.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[path = "../../../protocol/src/usb.rs"]
mod usb_wire;
pub mod usb { pub use crate::usb_wire::*; #[cfg(feature = "usb-webusb")] pub(crate) use crate::usb_ffi::web_admission; }
#[path = "../../src/runtime/usb/mod.rs"]
pub mod usb_runtime;
#[path = "../../src/runtime/webusb.rs"]
pub mod webusb_runtime;
pub mod runtime { pub use crate::usb_runtime as usb; pub use crate::webusb_runtime as webusb; }
#[path = "../../../ffi/src/usb.rs"]
mod usb_ffi;
#[cfg(feature = "usb-webusb")]
#[path = "../../../ffi/src/webusb_link.rs"]
mod webusb_link;

#[cfg(feature = "usb-webusb")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_web_blocked() -> u8 { unsafe { webusb_link::block_competitor() as u8 } }

#[cfg(feature = "usb-keyboard")]
#[path = "../../../ffi/src/keyboard_io.rs"]
mod keyboard_io;

#[cfg(feature = "usb-hid")]
#[path = "../../../ffi/src/hid_io.rs"]
mod hid_io;

#[path = "../../../ffi/src/ccid_io.rs"]
mod ccid_io;
