// SPDX-License-Identifier: Apache-2.0
//! Existing static product budgets; no dependency on a product Platform.
pub use canokey_ports::RequestLimits;

/// Presence can service only transport progress and device indications. It
/// cannot borrow request/response backing, storage, crypto or an application.
/// Calls are synchronous on the main loop; IRQs publish mailbox state only.
pub trait Presence {
    fn now(&mut self) -> u32;
    fn touched(&mut self) -> bool;
    fn contactless(&mut self) -> bool;
    /// False means cancel, disconnect, reset or replacement of the owner.
    fn progress(&mut self) -> bool;
    fn led(&mut self, on: bool);
    fn led_idle(&mut self);
    fn poll_presence(&mut self) -> bool;
}

// CanoKey Device already enforces the synchronous transport-only contract.
// This projection exposes only the subset needed by the shared presence code.
impl<T: canokey_ports::Device + ?Sized> Presence for T {
    fn now(&mut self) -> u32 {
        canokey_ports::Device::now(self)
    }
    fn touched(&mut self) -> bool {
        canokey_ports::Device::touched(self)
    }
    fn contactless(&mut self) -> bool {
        canokey_ports::Device::contactless(self)
    }
    fn progress(&mut self) -> bool {
        canokey_ports::Device::progress(self)
    }
    fn led(&mut self, on: bool) {
        canokey_ports::Device::led(self, on);
    }
    fn led_idle(&mut self) {
        canokey_ports::Device::led_idle(self);
    }
    fn poll_presence(&mut self) -> bool {
        canokey_ports::Device::poll_presence(self)
    }
}
