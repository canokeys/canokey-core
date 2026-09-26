// SPDX-License-Identifier: Apache-2.0
//! IRQ-visible keyboard transfer generation, separate from main-loop policy.
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
        let idle = ck_usb_tx_idle(0x81);
        ck_usb_dcd_unlock(mask);
        idle
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_io_send(report: *const u8, length: u8, generation: u32) -> u8 {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let ok = generation == EPOCH
            && !report.is_null()
            && matches!(length, 2 | 8)
            && ck_usb_submit(0x81, report, u16::from(length), 0) == 1;
        ck_usb_dcd_unlock(mask);
        u8::from(ok)
    }
}
