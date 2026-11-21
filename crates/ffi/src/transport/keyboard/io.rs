// SPDX-License-Identifier: Apache-2.0
//! IRQ-visible keyboard transfer generation, separate from main-loop policy.
use crate::transport::usb_io::{ck_usb_configured, ck_usb_submit, ck_usb_tx_idle};
use crate::transport::usb_locked;
use canokey_protocol::usb::*;
static mut EPOCH: u32 = 0;
pub unsafe fn ck_keyboard_packet_reset() {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        EPOCH = EPOCH.wrapping_add(1);
    });
}
pub unsafe fn ck_keyboard_io_epoch() -> u32 {
    // SAFETY: This reads the controller's IRQ-published scalar without borrowing the mailbox.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EPOCH)) }
}
pub unsafe fn ck_keyboard_io_configured() -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe { ck_usb_configured() })
}
pub unsafe fn ck_keyboard_io_idle() -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe { ck_usb_tx_idle(EP_KEYBOARD_IN) })
}
pub unsafe fn ck_keyboard_io_send(report: *const u8, length: u8, generation: u32) -> u8 {
    // SAFETY: The USB mask protects the IN lease and the caller keeps its report buffer live.
    usb_locked(|| unsafe {
        // Report ID1 plus seven keyboard bytes, or ID2 plus one consumer byte.
        let ok = generation == EPOCH
            && !report.is_null()
            && matches!(
                usize::from(length),
                CONSUMER_REPORT_BYTES | KEYBOARD_PACKET_BYTES
            )
            && ck_usb_submit(EP_KEYBOARD_IN, report, u16::from(length), 0) == 1;
        u8::from(ok)
    })
}
