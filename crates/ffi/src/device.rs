// SPDX-License-Identifier: Apache-2.0
//! Boot, mode and main-loop policy. Board callbacks perform hardware actions;
//! none may borrow Core. Settings notifications touch disjoint device state.
use canokey_rust_core::runtime::config;
unsafe extern "C" {
    fn ck_board_prepare();
    #[cfg(feature = "nfc")]
    fn ck_board_mode_pin() -> u8;
    fn ck_board_clock(mode: u8);
    #[cfg(feature = "nfc")]
    fn ck_board_nfc_irq_enable();
    fn ck_board_usb_ready() -> u8;
    fn ck_board_crypto_check(which: u8) -> u32;
    #[cfg(feature = "nfc")]
    fn ck_board_reset() -> !;
    fn ck_board_stack_paint();
    fn ck_board_stack_report();
    fn ck_platform_led(on: u8);
    fn device_delay(milliseconds: i32);
    fn ck_transport_progress() -> u8;
    fn ck_core_install() -> i32;
    fn ck_core_boot_flags(out: *mut u32) -> i32;
    #[cfg(feature = "storage")]
    fn ck_core_mark_initialized() -> i32;
    fn usb_device_init();
    fn ck_usb_set_landing(enabled: u8);
    fn CCID_Loop();
    #[cfg(feature = "storage")]
    fn ck_storage_init() -> i32;
    #[cfg(feature = "storage")]
    fn ck_storage_format() -> i32;
    #[cfg(feature = "usb-hid")]
    fn CTAPHID_Loop(waiting: u8) -> u8;
    #[cfg(feature = "ctap")]
    fn ck_core_presence_sample();
    #[cfg(feature = "usb-keyboard")]
    fn ck_keyboard_loop();
    #[cfg(feature = "usb-webusb")]
    fn WebUSB_Loop();
}
static mut LED_DEFAULT: bool = true;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_device_led_idle() {
    unsafe {
        #[cfg(feature = "nfc")]
        if super::nfc::is_nfc() != 0 {
            return;
        }
        ck_platform_led(LED_DEFAULT as u8);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_device_settings(flags: u32) {
    unsafe {
        LED_DEFAULT = flags & config::LED != 0;
        ck_usb_set_landing(u8::from(flags & config::WEBUSB != 0));
        ck_device_led_idle();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_device_progress() -> u8 {
    unsafe {
        device_delay(1);
        ck_transport_progress()
    }
}
unsafe fn blink(on_ms: i32, off_ms: i32) -> ! {
    loop {
        unsafe {
            ck_platform_led(1);
            device_delay(on_ms);
            ck_platform_led(0);
            device_delay(off_ms);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_device_main() -> ! {
    unsafe {
        ck_board_prepare();
        let mut flags = config::DEFAULT_FLAGS | config::INITIALIZED;
        let readable = ck_core_boot_flags(&mut flags) == 0;
        #[cfg(feature = "nfc")]
        let nfc_mode = readable && flags & config::NFC != 0 && ck_board_mode_pin() != 0;
        #[cfg(not(feature = "nfc"))]
        let nfc_mode = false;
        #[cfg(feature = "nfc")]
        super::nfc::ck_nfc_set_mode(nfc_mode as u8);
        ck_board_clock(nfc_mode as u8); // USB startup 40 MHz or contactless 20 MHz.
        if !readable {
            blink(10, 1000);
        }
        #[cfg(feature = "storage")]
        {
            // Only a known uninitialized page permits formatting. Mount errors
            // on provisioned devices are never permission to erase credentials.
            if flags & config::INITIALIZED == 0 && ck_storage_format() != 0 {
                blink(10, 1000);
            }
            if ck_storage_init() != 0 {
                blink(10, 1000);
            }
        }
        if ck_core_install() != 0 {
            blink(10, 1000);
        }
        #[cfg(feature = "nfc")]
        {
            if super::nfc::ck_nfc_configure() != 0 {
                blink(10, 1000);
            }
            if flags & config::NFC == 0 && super::nfc::ck_nfc_silence() != 0 {
                blink(10, 1000);
            }
        }
        #[cfg(feature = "storage")]
        if flags & config::INITIALIZED == 0 {
            if ck_core_mark_initialized() != 0 {
                blink(10, 1000);
            }
            // Match product first-boot acknowledgement. Power-cycle reloads
            // programmed chip EEPROM and starts the provisioned device.
            blink(50, 50);
        }
        if nfc_mode {
            #[cfg(feature = "nfc")]
            {
                super::nfc::nfc_init();
                ck_board_nfc_irq_enable();
            }
        } else {
            usb_device_init();
            while ck_board_usb_ready() == 0 {
                CCID_Loop();
            }
            ck_board_clock(2); // USB operating clock after enumeration.
            for primitive in 0..3 {
                if ck_board_crypto_check(primitive) != 0 {
                    blink(50, 50);
                }
            }
            ck_device_led_idle();
        }
        ck_board_stack_paint();
        loop {
            if nfc_mode {
                #[cfg(feature = "nfc")]
                {
                    super::nfc::nfc_loop();
                    if ck_board_mode_pin() == 0 {
                        ck_board_reset();
                    }
                }
            } else {
                #[cfg(feature = "ctap")]
                ck_core_presence_sample();
                #[cfg(feature = "usb-hid")]
                let _ = CTAPHID_Loop(0);
                CCID_Loop();
                #[cfg(feature = "usb-keyboard")]
                ck_keyboard_loop();
                #[cfg(feature = "usb-webusb")]
                WebUSB_Loop();
            }
            ck_board_stack_report();
        }
    }
}

#[cfg(feature = "platform-serial")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_device_serial(out: *mut u8) {
    if out.is_null() {
        return;
    }
    // Device callbacks may only read this independent raw config page. No
    // reentry into Core, LittleFS cache, crypto or the caller's workspace.
    let mut storage = unsafe { canokey_ports::native::StorageBackend::new() };
    let serial = config::serial(&mut storage);
    unsafe {
        core::ptr::copy_nonoverlapping(serial.as_ptr(), out, 4);
    }
}
