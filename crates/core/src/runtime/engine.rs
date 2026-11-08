// SPDX-License-Identifier: Apache-2.0
//! CanoKey application composition over the shared APDU engine.
#[cfg(any(feature = "ctap", feature = "pass"))]
use crate::ports::Platform;
#[cfg(any(feature = "ctap", feature = "pass"))]
use canokey_protocol::response::StatusWord as Sw;
use canokey_transport_runtime::engine as common;
pub(super) use common::DEFAULT_APDU_LE;
pub use common::{Dispatch, InputSource, Reply, Router};
pub(crate) const OWNER_APDU: u8 = 0x00;
pub(crate) const OWNER_WEBUSB: u8 = 0x03;
pub(crate) const OWNER_NFC: u8 = 0x04;
#[cfg(feature = "ctap")]
pub(crate) const OWNER_CTAP: u8 = 0x02;
pub struct CanoKeyOwners;
impl common::OwnerPolicy for CanoKeyOwners {
    const INVALID: u8 = OWNER_APDU;
    const NFC: u8 = OWNER_NFC;
    const EXTENDED_USB: u8 = OWNER_WEBUSB;
}
#[cfg(feature = "ctap")]
pub struct NativeHandoff {
    previous: Option<u8>,
}
#[cfg(feature = "ctap")]
impl common::Handoff for NativeHandoff {
    const INITIAL: Self = Self { previous: None };
    fn recover<C, R: Dispatch<C>>(
        &mut self,
        owner: &mut Option<u8>,
        router: &mut R,
        context: &mut C,
    ) {
        if *owner == Some(OWNER_CTAP) {
            router.yield_native(context);
            *owner = self.previous.take();
        }
    }
}
#[cfg(not(feature = "ctap"))]
pub type NativeHandoff = ();
pub type Runtime<R> = common::Runtime<R, CanoKeyOwners, NativeHandoff>;
#[repr(transparent)]
pub struct Core {
    runtime: Runtime<super::registry::Registry>,
}
impl core::ops::Deref for Core {
    type Target = Runtime<super::registry::Registry>;
    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}
impl core::ops::DerefMut for Core {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}
impl Core {
    pub const fn new() -> Self {
        Self {
            runtime: Runtime::with_router(super::registry::Registry::new()),
        }
    }
    #[cfg(feature = "ctap")]
    pub fn begin_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        // Admission has excluded pending APDU input/output and endpoint TX.
        // Keep card context separate from the temporary execution owner.
        if self.runtime.owner() != Some(OWNER_CTAP) {
            let previous = self.runtime.replace_owner(Some(OWNER_CTAP));
            self.runtime.handoff_mut().previous = previous;
        }
        self.runtime.router_mut().resume_ctap(p);
    }
    #[cfg(feature = "ctap")]
    pub fn begin_hid_request(
        &mut self,
        message_length: Option<usize>,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
        self.runtime
            .router_mut()
            .begin_hid_request(message_length, p);
    }
    #[cfg(feature = "ctap")]
    pub fn consume_hid_request(&mut self, bytes: &[u8]) {
        self.runtime.router_mut().consume_hid_request(bytes);
    }
    #[cfg(feature = "ctap")]
    pub fn finish_hid_request(
        &mut self,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.runtime.router_mut().finish_hid_request(p)
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap(
        &mut self,
        command: Result<crate::applets::ctap::Command, crate::applets::ctap::Status>,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.runtime.router_mut().execute_ctap(command, p)
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap_message(
        &mut self,
        command: crate::applets::ctap::message::Message,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.runtime.router_mut().execute_ctap_message(command, p)
    }
    #[cfg(feature = "ctap")]
    pub fn read_ctap(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        self.runtime.router_mut().read_ctap(offset, out, p)
    }
    #[cfg(feature = "ctap")]
    pub fn discard_ctap_continuation(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        // An idle HID reset/INIT must never close another transport's backing.
        if self.runtime.owner() == Some(OWNER_CTAP) {
            self.runtime.router_mut().close_ctap(p);
        }
    }
    #[cfg(feature = "ctap")]
    pub fn complete_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        self.runtime.router_mut().complete_ctap(p);
    }
    /// Serialized transport query after acknowledging the final HID report.
    #[cfg(feature = "ctap")]
    pub fn ctap_continuation_pending(&self) -> bool {
        self.runtime.owner() == Some(OWNER_CTAP) && self.runtime.router().native_pending()
    }
    #[cfg(feature = "ctap")]
    pub fn continue_ctap_message(
        &mut self,
        bytes: &[u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Option<usize> {
        self.runtime.router_mut().continue_ctap_message(bytes, p)
    }
    #[cfg(feature = "ctap")]
    pub fn close_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        self.runtime.router_mut().close_ctap(p);
    }
    pub const fn applet_count() -> u8 {
        cfg!(feature = "admin") as u8
            + cfg!(feature = "oath") as u8
            + cfg!(feature = "openpgp") as u8
            + cfg!(feature = "piv") as u8
            + cfg!(feature = "ndef") as u8
            + cfg!(feature = "ctap") as u8
    }
    #[cfg(feature = "pass")]
    pub fn touch(
        &self,
        index: u8,
        out: &mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Sw> {
        self.runtime.router().touch(index, out, p)
    }
    #[cfg(feature = "pass")]
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        self.runtime.router().challenge(index, input, out, p)
    }
}
impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}
