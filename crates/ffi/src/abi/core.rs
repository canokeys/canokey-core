// SPDX-License-Identifier: Apache-2.0
//! Compatibility C boundary; outer Rust compositions call composition::core.
use crate::{composition::core, platform::Native};
#[cfg(feature = "usb-ccid")]
pub(crate) use core::can_preempt;

#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_install() -> i32 {
    unsafe { core::install::<Native>() }
}
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_reset() {
    unsafe { core::reset::<Native>() }
}
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_slot_power() {
    unsafe { core::slot_power::<Native>() }
}
#[cfg(feature = "native-composition")]
#[unsafe(no_mangle)]
pub extern "C" fn ck_core_applet_count() -> u8 {
    core::applet_count()
}
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_exchange(
    owner: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    unsafe { core::exchange::<Native>(owner, input, len, out, capacity) }
}
#[cfg(all(feature = "pass", feature = "native-composition"))]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_touch(index: u8, out: *mut u8, capacity: usize) -> i32 {
    unsafe { core::touch::<Native>(index, out, capacity) }
}
#[cfg(all(feature = "pass", feature = "native-composition"))]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_challenge(
    index: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    unsafe { core::challenge::<Native>(index, input, len, out) }
}
#[cfg(all(
    feature = "pass",
    any(feature = "native-composition", feature = "usb-keyboard")
))]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_output_cancel(pressed: u8) {
    unsafe { core::output_cancel::<Native>(pressed) }
}
#[cfg(all(
    feature = "pass",
    any(feature = "native-composition", feature = "usb-keyboard")
))]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_output_sample(pressed: u8, now: u32, ready: u8) -> i32 {
    unsafe { core::output_sample::<Native>(pressed, now, ready) }
}
#[cfg(all(
    feature = "pass",
    any(feature = "native-composition", feature = "usb-keyboard")
))]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub extern "C" fn ck_core_keyboard_usage(ch: u8) -> i32 {
    core::keyboard_usage::<Native>(ch)
}
#[cfg(all(feature = "device-runtime", not(test)))]
pub(crate) fn boot_flags() -> Result<u32, canokey_ports::StorageError> {
    core::boot_flags::<Native>()
}
#[cfg(all(feature = "device-runtime", feature = "storage", not(test)))]
pub(crate) fn mark_initialized() -> Result<(), canokey_ports::StorageError> {
    core::mark_initialized::<Native>()
}
