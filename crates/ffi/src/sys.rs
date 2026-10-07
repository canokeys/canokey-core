// SPDX-License-Identifier: Apache-2.0
//! Platform imports shared by the serialized runtime and transport adapters.
#[cfg(all(test, feature = "nfc"))]
pub(crate) use crate::transport::nfc::tests::{
    ck_nfc_io_delay, ck_nfc_io_lock, ck_nfc_io_now, ck_nfc_io_read, ck_nfc_io_schedule,
    ck_nfc_io_select, ck_nfc_io_unlock, ck_nfc_io_write,
};
#[cfg(all(test, feature = "usb-device"))]
pub(crate) use crate::transport::usb::tests::{
    ck_usb_dcd_address, ck_usb_dcd_close, ck_usb_dcd_enable_irq, ck_usb_dcd_lock, ck_usb_dcd_open,
    ck_usb_dcd_ready, ck_usb_dcd_receive, ck_usb_dcd_stall, ck_usb_dcd_start, ck_usb_dcd_stop,
    ck_usb_dcd_unlock, ck_usb_dcd_write, device_get_tick,
};
unsafe extern "C" {
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_prepare();
    #[cfg(all(feature = "device-runtime", feature = "nfc"))]
    pub(crate) fn ck_board_mode_pin() -> u8;
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_clock(mode: u8);
    #[cfg(all(feature = "device-runtime", feature = "nfc"))]
    pub(crate) fn ck_board_nfc_irq_enable();
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_usb_ready() -> u8;
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_crypto_check(which: u8) -> u32;
    #[cfg(all(feature = "device-runtime", feature = "nfc"))]
    pub(crate) fn ck_board_reset() -> !;
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_stack_paint();
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_board_stack_report();
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_platform_led(on: u8);
    #[cfg(any(feature = "device-runtime", feature = "usb-hid"))]
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn device_delay(milliseconds: i32);
    #[cfg(all(feature = "device-runtime", feature = "storage"))]
    pub(crate) fn ck_storage_init() -> i32;
    #[cfg(all(feature = "device-runtime", feature = "storage"))]
    pub(crate) fn ck_storage_format() -> i32;
    #[cfg(feature = "device-runtime")]
    pub(crate) fn ck_timer_arm(milliseconds: u16);
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_lock() -> u32;
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_unlock(mask: u32);
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_read(address: u16, out: *mut u8, length: u8) -> i32;
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_write(address: u16, bytes: *const u8, length: u8) -> i32;
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_now() -> u32;
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_select(active: u8);
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_delay(milliseconds: u16);
    #[cfg(all(feature = "nfc", not(test)))]
    pub(crate) fn ck_nfc_io_schedule(callback: Option<unsafe extern "C" fn()>, milliseconds: u16);
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_size() -> usize;
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_acquire(owner: u8) -> i32;
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_release(owner: u8) -> i32;
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_clear() -> i32;
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_read(offset: usize, out: *mut u8, length: usize) -> i32;
    #[cfg(feature = "ctap")]
    pub(crate) fn pke_buffer_write(offset: usize, input: *const u8, length: usize) -> i32;
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_start();
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_enable_irq();
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_stop();
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_open(ep: u8);
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_close(ep: u8);
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_stall(ep: u8, halt: u8);
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_address(address: u8);
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_receive(ep: u8);
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_write(ep: u8, bytes: *const u8, length: u16) -> u8;
    #[cfg(all(feature = "usb-device", not(test)))]
    pub(crate) fn ck_usb_dcd_ready(ready: u8);
    #[cfg(any(
        feature = "usb-ccid",
        feature = "usb-hid",
        feature = "usb-keyboard",
        feature = "device-runtime"
    ))]
    #[cfg_attr(test, allow(dead_code))]
    #[cfg(not(all(test, feature = "usb-device")))]
    pub(crate) fn ck_usb_dcd_lock() -> u32;
    #[cfg(any(
        feature = "usb-ccid",
        feature = "usb-hid",
        feature = "usb-keyboard",
        feature = "device-runtime"
    ))]
    #[cfg_attr(test, allow(dead_code))]
    #[cfg(not(all(test, feature = "usb-device")))]
    pub(crate) fn ck_usb_dcd_unlock(mask: u32);
    #[cfg(feature = "usb-keyboard")]
    pub(crate) fn ck_platform_touched() -> u8;
    #[cfg(feature = "usb-keyboard")]
    pub(crate) fn ck_platform_now() -> u32;
    #[cfg(any(feature = "usb-ccid", feature = "usb-hid", feature = "usb-webusb"))]
    #[cfg_attr(test, allow(dead_code))]
    #[cfg(not(all(test, feature = "usb-device")))]
    pub(crate) fn device_get_tick() -> u32;
}
