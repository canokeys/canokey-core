// SPDX-License-Identifier: Apache-2.0
//! Optional compatibility C callbacks. Firmware exports belong to its platform.
#[cfg(any(feature = "usb-device", feature = "device-runtime", feature = "nfc"))]
use crate::composition;
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_init() {
    unsafe { composition::usb::init() }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_deinit() {
    unsafe { composition::usb::deinit() }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_bus_reset() {
    unsafe { composition::usb::bus_reset() }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_suspend() {
    unsafe { composition::usb::suspend() }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_resume() {
    unsafe { composition::usb::resume() }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_setup(bytes: *const u8, length: u16) {
    unsafe { composition::usb::setup(bytes, length) }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_in(endpoint: u8) {
    unsafe { composition::usb::in_event(endpoint) }
}
#[cfg(feature = "usb-device")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_out(endpoint: u8, bytes: *const u8, length: u16) -> u8 {
    unsafe { composition::usb::out_event(endpoint, bytes, length) }
}
#[cfg(feature = "device-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_timer_irq() {
    unsafe { composition::timer::irq() }
}
#[cfg(feature = "device-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_set_timeout(
    callback: Option<unsafe extern "C" fn()>,
    milliseconds: u16,
) {
    unsafe { composition::timer::set_timeout(callback, milliseconds) }
}
#[cfg(feature = "nfc")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfc_handler() {
    unsafe { composition::nfc::interrupt() }
}
#[cfg(feature = "nfc")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn is_nfc() -> u8 {
    unsafe { composition::nfc::mode() }
}
