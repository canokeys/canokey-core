// SPDX-License-Identifier: Apache-2.0
//! Outer backend selection for the serialized shared runtime.
//! Unsafe runtime entrypoints require one Provider for an installed runtime's
//! lifetime, including transport reset/cleanup: a lease must return to the
//! same staging backend that acquired it. IRQ callbacks never select a Provider.
use canokey_ports::{Backends, Platform};
pub mod core;
#[cfg(feature = "usb-hid")]
pub mod hid {
    pub use crate::transport::hid::link::{ck_hid_active as active, poll};
    pub unsafe fn keepalive(waiting: bool) {
        unsafe { crate::transport::hid::link::ck_hid_keepalive(u8::from(waiting)) }
    }
}
#[cfg(feature = "usb-ccid")]
pub mod ccid {
    pub use crate::transport::ccid::poll;
}
#[cfg(feature = "usb-webusb")]
pub mod webusb {
    pub use crate::transport::webusb::poll;
}
#[cfg(feature = "usb-device")]
pub mod usb {
    pub use crate::transport::usb::{
        ck_usb_configured as configured, ck_usb_in as in_event, ck_usb_out as out_event,
        ck_usb_setup as setup, progress, usb_device_deinit as deinit, usb_device_init as init,
    };
}

/// Capabilities constructed by the firmware, host or test owner.
///
/// Construction must not borrow transport state across Core execution: device
/// progress may service disjoint IRQ mailboxes while these capabilities are live.
pub trait Provider {
    type Backends: Backends;
    #[cfg(feature = "ctap")]
    type Staging: Staging;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T;
}

/// Serialized accelerator scratch, shared by HID and CCID request staging.
/// No backend may expose a hardware slice or release another owner's lease.
#[cfg(feature = "ctap")]
pub trait Staging {
    fn capacity() -> usize;
    fn acquire(owner: u8) -> bool;
    fn clear() -> bool;
    fn release(owner: u8) -> bool;
    fn read(offset: usize, out: &mut [u8]) -> bool;
    fn write(offset: usize, bytes: &[u8]) -> bool;
}
