// SPDX-License-Identifier: Apache-2.0
//! Serialized main-loop boundary; USB interrupts never access HID or CORE.
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
// Must match PKE_BUFFER_OWNER_CTAP in interfaces/rust-core/include/pke.h;
// this is an FFI ABI value, so keep the correspondence explicit.
const PKE_OWNER_CTAP: u8 = 3;
unsafe extern "C" {
    fn ck_ccid_idle() -> u8;
    fn ck_hid_execution_begin(cid: u32);
    fn ck_hid_execution_end();
    fn pke_buffer_size() -> usize;
    fn pke_buffer_acquire(owner: u8) -> i32;
    fn pke_buffer_release(owner: u8) -> i32;
    fn pke_buffer_clear() -> i32;
    fn pke_buffer_read(offset: usize, out: *mut u8, length: usize) -> i32;
    fn pke_buffer_write(offset: usize, input: *const u8, length: usize) -> i32;
}
struct RequestScratch;
// The backend owns only PKE bookkeeping, never a slice into hardware memory.
static mut PKE_LEASED: bool = false;
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
        unsafe { pke_buffer_size() }
    }
    fn begin(&mut self, use_pke: bool) -> Result<(), Error> {
        unsafe {
            if ck_ccid_idle() == 0 {
                return Err(Error::Busy);
            }
            // End the previous idle CCID session before staging any HID bytes.
            super::entrypoints::with_core(|core, p| core.begin_ctap(p));
            if use_pke {
                // A valid GET RESPONSE fits inline. Close a prior response
                // before new staged input borrows the accelerator workspace.
                super::entrypoints::with_core(|core, p| core.close_ctap(p));
                if pke_buffer_acquire(PKE_OWNER_CTAP) != 0 {
                    return Err(Error::Busy);
                }
                PKE_LEASED = true;
            }
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if unsafe { pke_buffer_write(offset, bytes.as_ptr(), bytes.len()) } == 0 {
            Ok(())
        } else {
            Err(Error::Other)
        }
    }
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if unsafe { pke_buffer_read(offset, bytes.as_mut_ptr(), bytes.len()) } == 0 {
            Ok(())
        } else {
            Err(Error::Other)
        }
    }
    fn begin_request(&mut self, message_length: Option<usize>) {
        super::entrypoints::with_core(|core, p| core.begin_hid_request(message_length, p));
    }
    fn consume_request(&mut self, bytes: &[u8]) {
        super::entrypoints::with_core(|core, _| core.consume_hid_request(bytes));
    }
    fn finish_request(&mut self, cid: u32) -> usize {
        unsafe { ck_hid_execution_begin(cid) };
        let length = super::entrypoints::with_core(|core, p| core.finish_hid_request(p));
        unsafe { ck_hid_execution_end() };
        length
    }
    #[inline(never)]
    fn wink(&mut self, cid: u32) -> usize {
        unsafe { ck_hid_execution_begin(cid) };
        let length = super::entrypoints::with_core(|core, p| {
            core.execute_ctap(Ok(canokey_rust_core::applets::ctap::Command::Wink), p)
        });
        unsafe { ck_hid_execution_end() };
        length
    }
    fn read_response(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        super::entrypoints::with_core(|core, p| core.read_ctap(offset, out, p))
            .map_err(|_| Error::Other)
    }
    fn close_response(&mut self) {
        super::entrypoints::with_core(|core, p| core.close_ctap(p));
    }
    fn complete_response(&mut self) {
        super::entrypoints::with_core(|core, p| core.complete_ctap(p));
    }
    fn discard_continuation(&mut self) {
        super::entrypoints::with_core(|core, p| core.discard_ctap_continuation(p));
    }
    fn continue_message(&mut self, bytes: &[u8]) -> Option<usize> {
        super::entrypoints::with_core(|core, p| core.continue_ctap_message(bytes, p))
    }

    fn close(&mut self) {
        unsafe {
            if PKE_LEASED {
                // Hardware cleanup failures deliberately halt here: reusing a
                // uncleared PKE lease could expose another request's secrets.
                assert_eq!(pke_buffer_clear(), 0);
                assert_eq!(pke_buffer_release(PKE_OWNER_CTAP), 0);
                PKE_LEASED = false;
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_reset() {
    unsafe {
        hid().reset(&mut RequestScratch);
        super::entrypoints::ck_core_reset();
    }
}
/// input is null or one full report; output is a distinct writable report.
/// Called only when the previous USB IN report has completed. Bit 0 indicates
/// output, bit 1 holds the shared session through RX and final TX completion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_poll(
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
