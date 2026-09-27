// SPDX-License-Identifier: Apache-2.0
// Production protocol, runtime and FFI; only register I/O and Core are mocked.
extern crate self as canokey_protocol;
extern crate self as canokey_rust_core;
#[path = "../../src/runtime/nfc.rs"]
pub mod link;
#[path = "../../../protocol/src/nfc.rs"]
mod wire;
// nfc_io resolves sibling runtime types, while Link resolves wire types through
// the protocol crate alias. Expose both namespaces at this fixture's root.
pub mod nfc {
    pub use crate::link::{Execution, HardwareAction, Irq, Recovery, irq};
    pub use crate::wire::*;
}
#[path = "../../src/runtime/nfc_io.rs"]
pub mod nfc_io;
#[path = "../../src/runtime/nfc_provision.rs"]
pub mod nfc_provision;
pub mod runtime {
    pub use crate::link as nfc;
    pub use crate::nfc_io;
    pub use crate::nfc_provision;
}
#[path = "../../../ffi/src/nfc.rs"]
mod facade;
