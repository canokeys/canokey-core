// SPDX-License-Identifier: Apache-2.0
//! Serialized main-loop boundary; USB interrupts never access HID or CORE.
#[cfg(feature = "usb-hid")]
use super::link::{ck_hid_execution_begin, ck_hid_execution_end};
#[cfg(feature = "usb-ccid")]
use crate::transport::ccid::ck_ccid_idle;
use crate::transport::pke_scratch::{self as pke, PkeLease};
use canokey_protocol::ctaphid::Error;
use canokey_rust_core::runtime::ctaphid::{Scratch, Transport};

crate::lazy_state!(
    HID,
    HID_READY,
    Transport,
    Transport::new(),
    initialize_hid,
    hid
);
unsafe extern "C" {
    #[cfg(not(feature = "usb-ccid"))]
    fn ck_ccid_idle() -> u8;
    #[cfg(not(feature = "usb-hid"))]
    fn ck_hid_execution_begin(cid: u32);
    #[cfg(not(feature = "usb-hid"))]
    fn ck_hid_execution_end();
}
struct RequestScratch;
// The backend owns only PKE bookkeeping, never a slice into hardware memory.
// Keep this byte out of LLVM's merged transport globals, whose padding otherwise
// grows when the HID helper exports become internal Rust functions.
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.ck_hid_pke_lease"))]
static mut PKE_LEASE: PkeLease = PkeLease::new();
impl Scratch for RequestScratch {
    fn webauthn_enabled(&mut self) -> bool {
        crate::platform::with_platform(|p| {
            canokey_rust_core::runtime::config::enabled(
                p.storage,
                canokey_rust_core::runtime::config::WEBAUTHN,
            )
        })
    }
    fn capacity(&self) -> usize {
        pke::capacity()
    }
    fn begin(&mut self, use_pke: bool) -> Result<(), Error> {
        unsafe {
            if ck_ccid_idle() == 0 {
                return Err(Error::Busy);
            }
            // End the previous idle CCID session before staging any HID bytes.
            crate::abi::core::with_core(|core, p| core.begin_ctap(p));
            if use_pke {
                // A valid GET RESPONSE fits inline. Close a prior response
                // before new staged input borrows the accelerator workspace.
                crate::abi::core::with_core(|core, p| core.close_ctap(p));
                if !(&mut *core::ptr::addr_of_mut!(PKE_LEASE)).acquire() {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if pke::write(offset, bytes) {
            Ok(())
        } else {
            Err(Error::Other)
        }
    }
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if pke::read(offset, bytes) {
            Ok(())
        } else {
            Err(Error::Other)
        }
    }
    fn begin_request(&mut self, message_length: Option<usize>) {
        crate::abi::core::with_core(|core, p| core.begin_hid_request(message_length, p));
    }
    fn consume_request(&mut self, bytes: &[u8]) {
        crate::abi::core::with_core(|core, _| core.consume_hid_request(bytes));
    }
    fn finish_request(&mut self, cid: u32) -> usize {
        unsafe { ck_hid_execution_begin(cid) };
        let length = crate::abi::core::with_core(|core, p| core.finish_hid_request(p));
        unsafe { ck_hid_execution_end() };
        length
    }
    #[inline(never)]
    fn wink(&mut self, cid: u32) -> usize {
        unsafe { ck_hid_execution_begin(cid) };
        let length = crate::abi::core::with_core(|core, p| {
            core.execute_ctap(Ok(canokey_rust_core::applets::ctap::Command::Wink), p)
        });
        unsafe { ck_hid_execution_end() };
        length
    }
    fn read_response(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        crate::abi::core::with_core(|core, p| core.read_ctap(offset, out, p))
            .map_err(|_| Error::Other)
    }
    fn close_response(&mut self) {
        crate::abi::core::with_core(|core, p| core.close_ctap(p));
    }
    fn complete_response(&mut self) {
        crate::abi::core::with_core(|core, p| core.complete_ctap(p));
    }
    fn discard_continuation(&mut self) {
        crate::abi::core::with_core(|core, p| core.discard_ctap_continuation(p));
    }
    fn continue_message(&mut self, bytes: &[u8]) -> Option<usize> {
        crate::abi::core::with_core(|core, p| core.continue_ctap_message(bytes, p))
    }

    fn close(&mut self) {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(PKE_LEASE)).close();
        }
    }
}
#[inline(never)]
pub unsafe fn ck_hid_reset() {
    unsafe {
        hid().reset(&mut RequestScratch);
        crate::abi::core::ck_core_reset();
    }
}
/// input is null or one full report; output is a distinct writable report.
/// Called only when the previous USB IN report has completed. Bit 0 indicates
/// output, bit 1 holds the shared session through RX and final TX completion.
#[inline(never)]
pub unsafe fn ck_hid_poll(
    input: *const [u8; 64],
    received: u32,
    now: u32,
    output: *mut [u8; 64],
) -> u8 {
    unsafe {
        let hid = hid();
        let out = &mut *output;
        let mut scratch = RequestScratch;
        hid.completed(&mut scratch);
        let produced = if let Some(input) = input.as_ref() {
            hid.receive(input, received, out, &mut scratch)
        } else {
            false
        };
        let produced =
            produced || hid.timeout(now, out, &mut scratch) || hid.transmit(out, &mut scratch);
        u8::from(produced) | (u8::from(hid.active()) << 1)
    }
}
