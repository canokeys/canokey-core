// SPDX-License-Identifier: Apache-2.0
//! Boot, mode and main-loop policy. Board callbacks perform hardware actions;
//! none may borrow Core. Settings notifications touch disjoint device state.
use canokey_rust_core::runtime::config;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(not(test))]
use crate::{abi, sys as hal, transport};
#[cfg(test)]
use tests::{abi, hal, transport};
// Stable u8 board ABI; keep values aligned with platform/rust-core/board.h.
const CLOCK_USB_STARTUP: u8 = 0;
const CLOCK_CONTACTLESS: u8 = 1;
const CLOCK_USB_OPERATING: u8 = 2;
// ck_board_crypto_check ABI in platform/rust-core/board.h: RNG=0, SM4=1, PKE=2.
// Keep the count aligned with CK_BOARD_CRYPTO_CHECK_COUNT when adding a check.
const CRYPTO_CHECK_COUNT: u8 = 3;
#[cfg(all(feature = "ctap", not(test)))]
use crate::platform::ck_core_presence_sample;
use hal::ck_board_clock;
use hal::ck_board_crypto_check;
#[cfg(feature = "nfc")]
use hal::ck_board_mode_pin;
#[cfg(feature = "nfc")]
use hal::ck_board_nfc_irq_enable;
use hal::ck_board_prepare;
#[cfg(feature = "nfc")]
use hal::ck_board_reset;
use hal::ck_board_stack_paint;
use hal::ck_board_stack_report;
use hal::ck_board_usb_ready;
use hal::ck_platform_led;
#[cfg(feature = "storage")]
use hal::ck_storage_format;
#[cfg(feature = "storage")]
use hal::ck_storage_init;
use hal::device_delay;
#[cfg(all(feature = "ctap", test))]
use tests::ck_core_presence_sample;
static mut LED_DEFAULT: bool = true;
pub unsafe fn ck_device_led_idle() {
    unsafe {
        #[cfg(feature = "nfc")]
        if transport::nfc::is_nfc() != 0 {
            return;
        }
        ck_platform_led(LED_DEFAULT as u8);
    }
}
pub unsafe fn ck_device_settings(flags: u32) {
    unsafe {
        LED_DEFAULT = flags & config::LED != 0;
        transport::usb::ck_usb_set_landing(u8::from(flags & config::WEBUSB != 0));
        ck_device_led_idle();
    }
}
pub unsafe fn ck_device_progress() -> u8 {
    unsafe {
        device_delay(1);
        transport::usb::ck_transport_progress()
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
    match unsafe { run() } {
        Stop::Blink(on, off) => unsafe { blink(on, off) },
        #[cfg(feature = "nfc")]
        Stop::Reset => unsafe { ck_board_reset() },
        #[cfg(test)]
        Stop::Iteration => panic!("bounded device run is test-only"),
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Blink(i32, i32),
    #[cfg(feature = "nfc")]
    Reset,
    #[cfg(test)]
    Iteration,
}
// Tests call this Rust runner directly; no panic/unwind crosses the C entrypoint.
unsafe fn run() -> Stop {
    unsafe {
        ck_board_prepare();
        let stored_flags = abi::core::boot_flags();
        let readable = stored_flags.is_ok();
        let flags = stored_flags.unwrap_or(config::DEFAULT_FLAGS | config::INITIALIZED);
        #[cfg(feature = "nfc")]
        let nfc_mode = readable && flags & config::NFC != 0 && ck_board_mode_pin() != 0;
        #[cfg(not(feature = "nfc"))]
        let nfc_mode = false;
        #[cfg(feature = "nfc")]
        transport::nfc::ck_nfc_set_mode(nfc_mode as u8);
        ck_board_clock(if nfc_mode {
            CLOCK_CONTACTLESS
        } else {
            CLOCK_USB_STARTUP
        });
        if !readable {
            return Stop::Blink(10, 1000);
        }
        #[cfg(feature = "storage")]
        {
            // Only a known uninitialized page permits formatting. Mount errors
            // on provisioned devices are never permission to erase credentials.
            if flags & config::INITIALIZED == 0 && ck_storage_format() != 0 {
                return Stop::Blink(10, 1000);
            }
            if ck_storage_init() != 0 {
                return Stop::Blink(10, 1000);
            }
        }
        if abi::core::ck_core_install() != 0 {
            return Stop::Blink(10, 1000);
        }
        #[cfg(feature = "nfc")]
        {
            if transport::nfc::ck_nfc_configure() != 0 {
                return Stop::Blink(10, 1000);
            }
            if flags & config::NFC == 0 && transport::nfc::ck_nfc_silence() != 0 {
                return Stop::Blink(10, 1000);
            }
        }
        #[cfg(feature = "storage")]
        if flags & config::INITIALIZED == 0 {
            if abi::core::mark_initialized().is_err() {
                return Stop::Blink(10, 1000);
            }
            // Match product first-boot acknowledgement. Power-cycle reloads
            // programmed chip EEPROM and starts the provisioned device.
            return Stop::Blink(50, 50);
        }
        if nfc_mode {
            #[cfg(feature = "nfc")]
            {
                transport::nfc::nfc_init();
                ck_board_nfc_irq_enable();
            }
        } else {
            transport::usb::usb_device_init();
            while ck_board_usb_ready() == 0 {
                transport::ccid::CCID_Loop();
            }
            ck_board_clock(CLOCK_USB_OPERATING);
            for primitive in 0..CRYPTO_CHECK_COUNT {
                if ck_board_crypto_check(primitive) != 0 {
                    return Stop::Blink(50, 50);
                }
            }
            ck_device_led_idle();
        }
        ck_board_stack_paint();
        #[cfg_attr(test, allow(clippy::never_loop))]
        // Unit runs stop after one main-loop iteration.
        loop {
            if nfc_mode {
                #[cfg(feature = "nfc")]
                {
                    transport::nfc::nfc_loop();
                    if ck_board_mode_pin() == 0 {
                        return Stop::Reset;
                    }
                }
            } else {
                #[cfg(feature = "ctap")]
                ck_core_presence_sample();
                #[cfg(feature = "usb-hid")]
                let _ = transport::hid::link::CTAPHID_Loop(0);
                transport::ccid::CCID_Loop();
                #[cfg(feature = "usb-keyboard")]
                transport::keyboard::ck_keyboard_loop();
                #[cfg(feature = "usb-webusb")]
                transport::webusb::WebUSB_Loop();
            }
            ck_board_stack_report();
            #[cfg(test)]
            return Stop::Iteration;
        }
    }
}

#[cfg(feature = "platform-serial")]
pub unsafe fn ck_device_serial(out: *mut u8) {
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
