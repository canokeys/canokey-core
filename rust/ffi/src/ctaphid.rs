// SPDX-License-Identifier: Apache-2.0
//! Serialized main-loop boundary; USB interrupts never access HID or CORE.
use canokey_protocol::ctaphid::Error;
use canokey_rust_core::runtime::ctaphid::{Scratch, Transport};

static mut HID: Transport = Transport::new();
const PKE_OWNER_CTAP: u8 = 3;
unsafe extern "C" {
    fn ck_ccid_idle() -> u8;
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
    fn begin(&mut self, use_pke: bool) -> Result<(), Error> {
        unsafe {
            if ck_ccid_idle() == 0 {
                return Err(Error::Busy);
            }
            // End the previous idle CCID session before staging any HID bytes.
            super::entrypoints::ck_core_reset();
            if use_pke {
                if pke_buffer_size() < canokey_rust_core::applets::ctap::MAX_REQUEST {
                    return Err(Error::Length);
                }
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
    fn close(&mut self) {
        unsafe {
            if PKE_LEASED {
                // Hardware cleanup failures must not silently reuse stale scratch.
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
        (&mut *core::ptr::addr_of_mut!(HID)).reset(&mut RequestScratch);
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
        let hid = &mut *core::ptr::addr_of_mut!(HID);
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
