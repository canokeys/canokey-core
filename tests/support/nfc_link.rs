// SPDX-License-Identifier: Apache-2.0
// Production protocol, runtime and FFI; only register I/O and Core are mocked.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[allow(dead_code)]
#[path = "../../crates/ffi/src/sys.rs"]
mod sys;
#[path = "../../crates/protocol/src/apdu.rs"]
pub mod apdu;
#[path = "../../crates/core/src/runtime/nfc.rs"]
pub mod link;
#[path = "../../crates/protocol/src/response.rs"]
pub mod response;
#[path = "../../crates/protocol/src/nfc.rs"]
mod wire;
// nfc_io resolves sibling runtime types, while Link resolves wire types through
// the protocol crate alias. Expose both namespaces at this fixture's root.
pub mod nfc {
    pub use crate::link::{Execution, HardwareAction, Irq, Recovery, irq};
    pub use crate::wire::*;
}
#[path = "../../crates/core/src/runtime/nfc_io.rs"]
pub mod nfc_io;
#[path = "../../crates/core/src/runtime/nfc_provision.rs"]
pub mod nfc_provision;
pub mod runtime {
    pub use crate::link as nfc;
    pub use crate::nfc_io;
    pub use crate::nfc_provision;
}
#[path = "../../crates/ffi/src/transport/nfc.rs"]
mod facade;
#[path = "../../crates/ffi/src/transport/owners.rs"]
mod owners;

mod transport {
    pub(crate) use crate::owners;
    pub(crate) mod usb {
        unsafe extern "C" {
            pub fn usb_device_deinit();
        }
    }
    pub(crate) mod ccid {
        unsafe extern "C" {
            pub fn ck_ccid_response_buffer() -> *mut u8;
        }
    }
}
mod abi {
    pub(crate) mod core {
        unsafe extern "C" {
            pub fn ck_core_reset();
            pub fn ck_core_exchange(
                owner: u8,
                input: *const u8,
                length: usize,
                output: *mut u8,
                capacity: usize,
            ) -> i32;
        }
    }
}
