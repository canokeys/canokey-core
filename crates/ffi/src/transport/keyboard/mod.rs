// SPDX-License-Identifier: Apache-2.0
//! Main-loop keyboard policy; hardware reset notifications remain in a mailbox.
use self::io::{
    ck_keyboard_io_configured, ck_keyboard_io_epoch, ck_keyboard_io_idle, ck_keyboard_io_send,
};
use crate::composition::{Provider, core as core_ops};
use crate::sys::ck_platform_now;
use crate::sys::ck_platform_touched;
use crate::transport::ccid::ck_ccid_scratch_busy;
#[cfg(feature = "ctap")]
use crate::transport::hid::link::ck_hid_busy;
use canokey_rust_core::runtime::keyboard::Keyboard;
static mut KEYBOARD: Keyboard = Keyboard::new();
static mut REPORT: [u8; 8] = [0; 8];
static mut EPOCH: u32 = 0;
static mut PENDING: u8 = 0;
static mut RESET_OUTPUT: bool = false;

trait Io {
    fn contactless(&mut self) -> bool;
    fn web_busy(&mut self) -> bool;
    fn competing(&mut self) -> bool;
    fn epoch(&mut self) -> u32;
    fn configured(&mut self) -> bool;
    fn idle(&mut self) -> bool;
    fn touched(&mut self) -> u8;
    fn now(&mut self) -> u32;
    fn cancel(&mut self, pressed: u8);
    fn sample(&mut self, pressed: u8, now: u32, ready: bool) -> i32;
    fn usage(&mut self, ch: u8) -> i32;
    // The serialized caller keeps REPORT fixed until the controller completes.
    unsafe fn send(&mut self, report: *const u8, length: u8, epoch: u32) -> bool;
}

struct Native<P>(core::marker::PhantomData<P>);
impl<P: Provider> Io for Native<P> {
    fn contactless(&mut self) -> bool {
        #[cfg(feature = "nfc")]
        return unsafe { crate::transport::nfc::is_nfc() != 0 };
        #[cfg(not(feature = "nfc"))]
        false
    }
    fn web_busy(&mut self) -> bool {
        #[cfg(feature = "usb-webusb")]
        return unsafe { crate::transport::webusb::block_competitor() };
        #[cfg(not(feature = "usb-webusb"))]
        false
    }
    fn competing(&mut self) -> bool {
        #[cfg(feature = "ctap")]
        if unsafe { ck_hid_busy() != 0 } {
            return true;
        }
        unsafe { ck_ccid_scratch_busy() != 0 }
    }
    fn epoch(&mut self) -> u32 {
        unsafe { ck_keyboard_io_epoch() }
    }
    fn configured(&mut self) -> bool {
        unsafe { ck_keyboard_io_configured() != 0 }
    }
    fn idle(&mut self) -> bool {
        unsafe { ck_keyboard_io_idle() != 0 }
    }
    fn touched(&mut self) -> u8 {
        unsafe { ck_platform_touched() }
    }
    fn now(&mut self) -> u32 {
        unsafe { ck_platform_now() }
    }
    fn cancel(&mut self, pressed: u8) {
        unsafe { core_ops::output_cancel::<P>(pressed) }
    }
    fn sample(&mut self, pressed: u8, now: u32, ready: bool) -> i32 {
        unsafe { core_ops::output_sample::<P>(pressed, now, u8::from(ready)) }
    }
    fn usage(&mut self, ch: u8) -> i32 {
        core_ops::keyboard_usage::<P>(ch)
    }
    unsafe fn send(&mut self, report: *const u8, length: u8, epoch: u32) -> bool {
        unsafe { ck_keyboard_io_send(report, length, epoch) != 0 }
    }
}

unsafe fn flush_pending(io: &mut impl Io, epoch: u32) {
    unsafe {
        if PENDING != 0 && io.send(core::ptr::addr_of!(REPORT).cast(), PENDING, epoch) {
            (&mut *core::ptr::addr_of_mut!(KEYBOARD)).accepted(REPORT[0]);
            PENDING = 0;
        }
    }
}
#[inline(never)]
#[cfg(feature = "native-composition")]
pub unsafe fn ck_keyboard_loop() {
    unsafe { poll_provider::<crate::platform::Native>() }
}

#[inline(never)]
pub unsafe fn poll_provider<P: Provider>() {
    unsafe { poll(&mut Native::<P>(core::marker::PhantomData)) }
}

unsafe fn poll(io: &mut impl Io) {
    unsafe {
        if io.contactless() {
            return;
        }
        let web_busy = io.web_busy();
        let epoch = io.epoch();
        if EPOCH != epoch {
            EPOCH = epoch;
            KEYBOARD = Keyboard::new();
            PENDING = 0;
            RESET_OUTPUT = true;
        }
        if !io.configured() {
            return;
        }
        if web_busy {
            // Finish a previously submitted key release without entering Core.
            // WebUSB may own the session while the keyboard IN completes.
            if io.idle() {
                PENDING = (&*core::ptr::addr_of!(KEYBOARD))
                    .prepare(None, &mut *core::ptr::addr_of_mut!(REPORT))
                    .unwrap_or(0) as u8;
                flush_pending(io, epoch);
            }
            return;
        }
        if io.competing() {
            return;
        }
        if RESET_OUTPUT {
            let pressed = io.touched();
            io.cancel(pressed);
            RESET_OUTPUT = false;
        }
        let idle = io.idle();
        let ready = (&*core::ptr::addr_of!(KEYBOARD)).ready(idle) && PENDING == 0;
        // Sample touch even while a report is owned by the controller.
        let pressed = io.touched();
        let now = io.now();
        let ch = io.sample(pressed, now, ready);
        if !idle || epoch != io.epoch() {
            return;
        }
        if PENDING == 0 {
            let keyboard = &*core::ptr::addr_of!(KEYBOARD);
            let report = &mut *core::ptr::addr_of_mut!(REPORT);
            PENDING = if ch == i32::from(canokey_protocol::usb::EJECT_SENTINEL) {
                keyboard.prepare_eject(report)
            } else {
                let usage = u8::try_from(ch).ok().and_then(|ch| {
                    let encoded = io.usage(ch);
                    // ABI packs modifier in the high byte, usage in the low byte.
                    (encoded >= 0).then_some(((encoded >> 8) as u8, encoded as u8))
                });
                keyboard.prepare_usage(usage, report)
            }
            .unwrap_or(0) as u8;
        }
        flush_pending(io, epoch);
    }
}

pub(crate) mod io;

#[cfg(test)]
mod tests;
