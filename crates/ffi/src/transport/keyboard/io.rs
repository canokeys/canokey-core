// SPDX-License-Identifier: Apache-2.0
//! IRQ-visible keyboard transfer generation, separate from main-loop policy.
use canokey_protocol::usb::*;
unsafe extern "C" {
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
    fn ck_usb_configured() -> u8;
    fn ck_usb_tx_idle(endpoint: u8) -> u8;
    fn ck_usb_submit(endpoint: u8, bytes: *const u8, length: u16, zlp: u8) -> i32;
}
static mut EPOCH: u32 = 0;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_packet_reset() {
    unsafe {
        let mask = ck_usb_dcd_lock();
        EPOCH = EPOCH.wrapping_add(1);
        ck_usb_dcd_unlock(mask);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_io_epoch() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EPOCH)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_io_configured() -> u8 {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let configured = ck_usb_configured();
        ck_usb_dcd_unlock(mask);
        configured
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_io_idle() -> u8 {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let idle = ck_usb_tx_idle(EP_KEYBOARD_IN);
        ck_usb_dcd_unlock(mask);
        idle
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_io_send(report: *const u8, length: u8, generation: u32) -> u8 {
    unsafe {
        let mask = ck_usb_dcd_lock();
        // Report ID1 plus seven keyboard bytes, or ID2 plus one consumer byte.
        let ok = generation == EPOCH
            && !report.is_null()
            && matches!(
                usize::from(length),
                CONSUMER_REPORT_BYTES | KEYBOARD_PACKET_BYTES
            )
            && ck_usb_submit(EP_KEYBOARD_IN, report, u16::from(length), 0) == 1;
        ck_usb_dcd_unlock(mask);
        u8::from(ok)
    }
}
