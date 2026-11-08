// SPDX-License-Identifier: Apache-2.0
//! Existing static product budgets; no dependency on a product Platform.
pub use canokey_ports::RequestLimits;

/// Stage only a provisioned certificate. The product grants authority before
/// borrowing this capability and fixes the destination record in its adapter.
/// Each operation returns before another application or transport can run.
pub trait CertificateStage {
    type Error;
    fn begin(&mut self) -> Result<(), Self::Error>;
    fn append(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    fn commit(&mut self) -> Result<(), Self::Error>;
    fn abort(&mut self);
}

/// Read only the provisioned certificate. No source handle or output borrow
/// escapes this call. Products retain validation, backing and close ownership;
/// exact and partial modes preserve distinct backend error/short-read behavior.
pub trait Certificate {
    type Error;
    fn read(
        &mut self,
        offset: u32,
        output: &mut [u8],
        mode: crate::response::ReadMode,
    ) -> Result<usize, Self::Error>;
}

/// Read only provisioned attestation key bytes and certificate metadata. Product
/// adapters validate their own records and retain error/missing semantics.
/// This synchronous capability cannot sign, install, write or retain a secret.
pub trait Attestation {
    type Error;
    fn key(
        &mut self,
        out: &mut [u8; crate::provision::PRIVATE_KEY_BYTES],
    ) -> Result<usize, Self::Error>;
    fn certificate_length(&mut self) -> Result<usize, Self::Error>;
}

/// Access only the provisioned SM2 identifier record. This synchronous borrow
/// exposes neither general storage nor authorization/session/application state.
pub trait Sm2Settings {
    fn load(
        &mut self,
        out: &mut [u8; crate::settings::RECORD_BYTES],
    ) -> Result<usize, canokey_ports::StorageError>;
    fn replace(&mut self, wire: &[u8]) -> Result<(), canokey_ports::StorageError>;
}

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
