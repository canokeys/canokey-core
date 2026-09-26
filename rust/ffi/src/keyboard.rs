// SPDX-License-Identifier: Apache-2.0
//! Main-loop keyboard policy; hardware reset notifications remain in a mailbox.
use canokey_rust_core::runtime::keyboard::Keyboard;
unsafe extern "C" {
    fn ck_keyboard_io_epoch() -> u32;
    fn ck_keyboard_io_configured() -> u8;
    fn ck_keyboard_io_idle() -> u8;
    fn ck_keyboard_io_send(report: *mut u8, len: u8, epoch: u32) -> u8;
    fn ck_platform_touched() -> u8;
    fn ck_platform_now() -> u32;
    fn ck_core_output_cancel(pressed: u8);
    fn ck_core_output_sample(pressed: u8, now: u32, ready: u8) -> i32;
    fn ck_ccid_scratch_busy() -> u8;
    #[cfg(feature = "ctap")]
    fn ck_hid_busy() -> u8;
}
static mut KEYBOARD: Keyboard = Keyboard::new();
static mut REPORT: [u8; 8] = [0; 8];
static mut EPOCH: u32 = 0;
static mut PENDING: u8 = 0;
static mut RESET_OUTPUT: bool = false;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_keyboard_loop() {
    unsafe {
        #[cfg(feature = "nfc")]
        if super::nfc::is_nfc() != 0 {
            return;
        }
        #[cfg(feature = "usb-webusb")]
        let web_busy = super::webusb_link::block_competitor();
        let epoch = ck_keyboard_io_epoch();
        if EPOCH != epoch {
            EPOCH = epoch;
            KEYBOARD = Keyboard::new();
            PENDING = 0;
            RESET_OUTPUT = true;
        }
        if ck_keyboard_io_configured() == 0 {
            return;
        }
        #[cfg(feature = "usb-webusb")]
        if web_busy {
            // Finish a previously submitted key release without entering Core.
            // WebUSB may own the session while the keyboard IN completes.
            if ck_keyboard_io_idle() != 0 {
                PENDING = (&*core::ptr::addr_of!(KEYBOARD))
                    .prepare(None, &mut *core::ptr::addr_of_mut!(REPORT))
                    .unwrap_or(0) as u8;
                if PENDING != 0
                    && ck_keyboard_io_send(core::ptr::addr_of_mut!(REPORT).cast(), PENDING, epoch)
                        != 0
                {
                    (&mut *core::ptr::addr_of_mut!(KEYBOARD)).accepted(REPORT[0]);
                    PENDING = 0;
                }
            }
            return;
        }
        #[cfg(feature = "ctap")]
        if ck_hid_busy() != 0 {
            return;
        }
        if ck_ccid_scratch_busy() != 0 {
            return;
        }
        if RESET_OUTPUT {
            ck_core_output_cancel(ck_platform_touched());
            RESET_OUTPUT = false;
        }
        let idle = ck_keyboard_io_idle() != 0;
        let ready = (&*core::ptr::addr_of!(KEYBOARD)).ready(idle) && PENDING == 0;
        // Sample touch even while a report is owned by the controller.
        let ch = ck_core_output_sample(ck_platform_touched(), ck_platform_now(), u8::from(ready));
        if !idle || epoch != ck_keyboard_io_epoch() {
            return;
        }
        if PENDING == 0 {
            PENDING = (&*core::ptr::addr_of!(KEYBOARD))
                .prepare(u8::try_from(ch).ok(), &mut *core::ptr::addr_of_mut!(REPORT))
                .unwrap_or(0) as u8;
        }
        if PENDING != 0
            && ck_keyboard_io_send(core::ptr::addr_of_mut!(REPORT).cast(), PENDING, epoch) != 0
        {
            (&mut *core::ptr::addr_of_mut!(KEYBOARD)).accepted(REPORT[0]);
            PENDING = 0;
        }
    }
}
