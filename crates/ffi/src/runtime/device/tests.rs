// SPDX-License-Identifier: Apache-2.0
//! Bounded boot/loop runner; substitutions never unwind through a C boundary.
use super::*;
#[derive(Default)]
#[cfg_attr(
    not(all(
        feature = "storage",
        feature = "nfc",
        feature = "usb-hid",
        feature = "usb-keyboard",
        feature = "usb-webusb"
    )),
    allow(dead_code)
)] // Reduced profiles exercise the timer without every boot-policy counter.
struct Board {
    scenario: usize,
    flags: u32,
    masked: u32,
    armed: u16,
    callbacks: usize,
    formatted: usize,
    mounted: usize,
    installed: usize,
    marked: usize,
    configured: usize,
    silenced: usize,
    usb: usize,
    clock: u8,
    checks: usize,
    irq: usize,
    ccid: usize,
    hid: usize,
    keyboard: usize,
    webusb: usize,
    presence: usize,
    nfc_loop: usize,
    active: bool,
    led: u8,
    landing: u8,
    painted: usize,
    reports: usize,
}
static BOARD: std::sync::Mutex<Board> = std::sync::Mutex::new(Board {
    scenario: 0,
    flags: 0,
    masked: 0,
    armed: 0,
    callbacks: 0,
    formatted: 0,
    mounted: 0,
    installed: 0,
    marked: 0,
    configured: 0,
    silenced: 0,
    usb: 0,
    clock: 0,
    checks: 0,
    irq: 0,
    ccid: 0,
    hid: 0,
    keyboard: 0,
    webusb: 0,
    presence: 0,
    nfc_loop: 0,
    active: false,
    led: 0,
    landing: 0,
    painted: 0,
    reports: 0,
});
fn board() -> std::sync::MutexGuard<'static, Board> {
    BOARD.lock().unwrap()
}
// Unit substitutions are Rust functions, including nonreturning hardware hooks
// that the bounded runner returns before invoking.
pub(crate) mod hal {
    use super::*;
    pub(crate) unsafe fn ck_board_prepare() {}
    pub(crate) unsafe fn ck_board_clock(mode: u8) {
        board().clock = mode;
    }
    pub(crate) unsafe fn ck_board_crypto_check(which: u8) -> u32 {
        let mut b = board();
        assert_eq!(b.clock, CLOCK_USB_OPERATING);
        assert_eq!(usize::from(which), b.checks);
        b.checks += 1;
        u32::from(b.scenario == 8 && which == 1)
    }
    #[cfg(feature = "nfc")]
    pub(crate) unsafe fn ck_board_mode_pin() -> u8 {
        let b = board();
        u8::from(if b.scenario == 1 {
            b.nfc_loop == 0
        } else {
            b.scenario == 7
        })
    }
    #[cfg(feature = "nfc")]
    pub(crate) unsafe fn ck_board_nfc_irq_enable() {
        board().irq += 1;
    }
    #[cfg(feature = "nfc")]
    pub(crate) unsafe fn ck_board_reset() -> ! {
        panic!("runner must return Reset")
    }
    pub(crate) unsafe fn ck_board_stack_paint() {
        let mut b = board();
        assert_eq!(b.installed, 1);
        assert_eq!(b.marked, 0);
        b.painted += 1;
    }
    pub(crate) unsafe fn ck_board_stack_report() {
        board().reports += 1;
    }
    pub(crate) unsafe fn ck_board_usb_ready() -> u8 {
        u8::from(board().ccid != 0)
    }
    pub(crate) unsafe fn ck_platform_led(on: u8) {
        board().led = on;
    }
    #[cfg(feature = "storage")]
    pub(crate) unsafe fn ck_storage_format() -> i32 {
        let mut b = board();
        assert_eq!(b.flags & config::INITIALIZED, 0);
        b.formatted += 1;
        if b.scenario == 5 { -1 } else { 0 }
    }
    #[cfg(feature = "storage")]
    pub(crate) unsafe fn ck_storage_init() -> i32 {
        let mut b = board();
        b.mounted += 1;
        if b.scenario == 3 { -1 } else { 0 }
    }
    pub(crate) unsafe fn device_delay(milliseconds: i32) {
        assert_eq!(milliseconds, 1);
    }
    pub(crate) unsafe fn ck_timer_arm(milliseconds: u16) {
        let mut b = board();
        assert_ne!(b.masked, 0);
        b.armed = milliseconds;
    }
    pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
        let prior = {
            let mut b = board();
            let prior = b.masked;
            b.masked = 1;
            prior
        };
        let result = run();
        board().masked = prior;
        result
    }
}
pub(crate) mod abi {
    pub(crate) mod core {
        use super::super::*;
        pub(crate) fn boot_flags() -> Result<u32, canokey_ports::StorageError> {
            let b = board();
            if b.scenario == 4 {
                Err(canokey_ports::StorageError::Unavailable)
            } else {
                Ok(b.flags)
            }
        }
        pub(crate) unsafe fn ck_core_install() -> i32 {
            let flags = {
                let mut b = board();
                assert_eq!(b.mounted, 1);
                b.installed += 1;
                b.flags
            };
            unsafe { ck_device_settings(flags) };
            0
        }
        #[cfg(feature = "storage")]
        pub(crate) fn mark_initialized() -> Result<(), canokey_ports::StorageError> {
            let mut b = board();
            assert_eq!(b.formatted, 1);
            assert_eq!(b.installed, 1);
            #[cfg(feature = "nfc")]
            assert_eq!(b.configured, 1);
            b.marked += 1;
            Ok(())
        }
    }
}
#[cfg(feature = "ctap")]
pub(crate) unsafe fn ck_core_presence_sample() {
    board().presence += 1;
}
pub(crate) mod transport {
    #[cfg(feature = "nfc")]
    pub(crate) mod nfc {
        use super::super::*;
        pub(crate) unsafe fn is_nfc() -> u8 {
            u8::from(board().active)
        }
        pub(crate) unsafe fn ck_nfc_set_mode(active: u8) {
            board().active = active != 0;
        }
        pub(crate) unsafe fn ck_nfc_configure() -> i32 {
            let mut b = board();
            b.configured += 1;
            if b.scenario == 6 { -1 } else { 0 }
        }
        pub(crate) unsafe fn ck_nfc_silence() -> i32 {
            let mut b = board();
            assert_eq!(b.flags & config::NFC, 0);
            b.silenced += 1;
            0
        }
        pub(crate) unsafe fn nfc_init() {
            let b = board();
            assert!(b.active);
            assert_eq!(b.installed, 1);
            assert_eq!(b.configured, 1);
            assert_eq!(b.usb, 0);
        }
        pub(crate) unsafe fn nfc_loop() {
            board().nfc_loop += 1;
        }
    }
    pub(crate) mod usb {
        use super::super::*;
        pub(crate) unsafe fn ck_usb_set_landing(enabled: u8) {
            board().landing = enabled;
        }
        pub(crate) unsafe fn ck_transport_progress() -> u8 {
            1
        }
        pub(crate) unsafe fn usb_device_init() {
            let mut b = board();
            assert!(!b.active);
            assert_eq!(b.installed, 1);
            #[cfg(feature = "nfc")]
            assert_eq!(b.configured, 1);
            b.usb += 1;
        }
    }
    pub(crate) mod ccid {
        #[allow(non_snake_case)]
        pub(crate) unsafe fn CCID_Loop() {
            super::super::board().ccid += 1;
        }
    }
    #[cfg(feature = "usb-hid")]
    pub(crate) mod hid {
        pub(crate) mod link {
            #[allow(non_snake_case)]
            pub(crate) unsafe fn CTAPHID_Loop(wait: u8) -> u8 {
                assert_eq!(wait, 0);
                super::super::super::board().hid += 1;
                0
            }
        }
    }
    #[cfg(feature = "usb-keyboard")]
    pub(crate) mod keyboard {
        pub(crate) unsafe fn ck_keyboard_loop() {
            super::super::board().keyboard += 1;
        }
    }
    #[cfg(feature = "usb-webusb")]
    pub(crate) mod webusb {
        #[allow(non_snake_case)]
        pub(crate) unsafe fn WebUSB_Loop() {
            super::super::board().webusb += 1;
        }
    }
}
unsafe extern "C" fn timer_callback() {
    let callbacks = {
        let mut b = board();
        assert_eq!(b.armed, 0);
        b.callbacks += 1;
        b.callbacks
    };
    if callbacks == 1 {
        unsafe { super::super::timer::device_set_timeout(Some(timer_callback), 20) };
    }
}
#[test]
fn device_timer_rearming_cancellation_and_irq_mask() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    *board() = Board::default();
    use super::super::timer::{ck_timer_irq, device_set_timeout};
    unsafe {
        device_set_timeout(Some(timer_callback), 10);
        assert_eq!(board().armed, 10);
        assert_eq!(board().masked, 0);
        ck_timer_irq();
        assert_eq!(board().callbacks, 1);
        assert_eq!(board().armed, 20);
        assert_eq!(board().masked, 0);
        ck_timer_irq();
        assert_eq!(board().callbacks, 2);
        assert_eq!(board().armed, 0);
        assert_eq!(board().masked, 0);
        ck_timer_irq();
        assert_eq!(board().callbacks, 2);
        device_set_timeout(Some(timer_callback), 10);
        device_set_timeout(None, 0);
        ck_timer_irq();
        assert_eq!(board().callbacks, 2);
        device_set_timeout(Some(timer_callback), 0);
        ck_timer_irq();
        assert_eq!(board().callbacks, 2);
        board().masked = 1;
        device_set_timeout(Some(timer_callback), 3);
        assert_eq!(board().masked, 1);
        assert_eq!(board().armed, 3);
        ck_timer_irq();
        assert_eq!(board().masked, 1);
        assert_eq!(board().callbacks, 3);
    }
    board().masked = 0;
}
#[cfg(all(
    feature = "storage",
    feature = "nfc",
    feature = "usb-hid",
    feature = "usb-keyboard",
    feature = "usb-webusb"
))]
#[test]
fn device_boot_modes_failures_settings_and_loop() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    for scenario in 0..10 {
        let mut flags = config::DEFAULT_FLAGS | config::INITIALIZED;
        if scenario == 2 || scenario == 5 {
            flags &= !config::INITIALIZED;
        }
        if scenario == 7 {
            flags &= !config::NFC;
        }
        if scenario == 9 {
            flags &= !(config::LED | config::WEBUSB);
        }
        *board() = Board {
            scenario,
            flags,
            ..Board::default()
        };
        let result = unsafe { run() };
        let b = board();
        match scenario {
            0 | 7 | 9 => {
                assert_eq!(result, Stop::Iteration);
                assert_eq!(b.formatted, 0);
                assert_eq!(b.mounted, 1);
                assert_eq!(b.installed, 1);
                assert_eq!(b.marked, 0);
                assert_eq!(b.configured, 1);
                assert_eq!(b.usb, 1);
                assert_eq!(b.checks, 3);
                assert_eq!(b.irq, 0);
                assert_eq!(b.ccid, 2);
                assert_eq!(b.hid, 1);
                assert_eq!(b.keyboard, 1);
                assert_eq!(b.webusb, 1);
                assert_eq!(b.presence, 1);
                assert_eq!(b.silenced, usize::from(scenario == 7));
                assert_eq!(b.landing, u8::from(scenario != 9));
                assert_eq!(b.led, u8::from(scenario != 9));
                assert_eq!(b.painted, 1);
                assert_eq!(b.reports, 1);
            }
            1 => {
                assert_eq!(result, Stop::Reset);
                assert!(b.active);
                assert_eq!(b.clock, CLOCK_CONTACTLESS);
                assert_eq!(b.nfc_loop, 1);
                assert_eq!(b.irq, 1);
                assert_eq!(b.usb, 0);
                assert_eq!(
                    b.checks + b.formatted + b.ccid + b.hid + b.keyboard + b.webusb + b.presence,
                    0
                );
            }
            2 => {
                assert_eq!(result, Stop::Blink(50, 50));
                assert_eq!(b.formatted, 1);
                assert_eq!(b.mounted, 1);
                assert_eq!(b.installed, 1);
                assert_eq!(b.marked, 1);
                assert_eq!(b.usb, 0);
            }
            3 => {
                assert_eq!(result, Stop::Blink(10, 1000));
                assert_eq!(b.formatted, 0);
                assert_eq!(b.mounted, 1);
                assert_eq!(b.installed, 0);
            }
            4 => {
                assert_eq!(result, Stop::Blink(10, 1000));
                assert_eq!(b.formatted + b.mounted + b.installed, 0);
            }
            5 => {
                assert_eq!(result, Stop::Blink(10, 1000));
                assert_eq!(b.formatted, 1);
                assert_eq!(b.mounted + b.installed, 0);
            }
            6 => {
                assert_eq!(result, Stop::Blink(10, 1000));
                assert_eq!(b.installed, 1);
                assert_eq!(b.configured, 1);
                assert_eq!(b.usb, 0);
            }
            8 => {
                assert_eq!(result, Stop::Blink(50, 50));
                assert_eq!(b.checks, 2);
                assert_eq!(b.usb, 1);
                assert_eq!(b.hid, 0);
            }
            _ => unreachable!(),
        }
    }
}
