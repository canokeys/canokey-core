// SPDX-License-Identifier: Apache-2.0
//! Device callbacks and volatile secret erasure adapter.
use canokey_rust_core::ports::{Device, Memory};

pub(super) struct DeviceBackend;
pub(super) struct MemoryBackend;

#[cfg(feature = "platform-device")]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
}
#[cfg(feature = "platform-serial")]
unsafe extern "C" {
    fn ck_platform_serial(out: *mut u8);
}
#[cfg(feature = "ctap")]
unsafe extern "C" {
    fn ck_hid_keepalive(waiting: u8);
}
#[cfg(feature = "ctap")]
static mut PRESENCE: canokey_rust_core::runtime::Polling =
    canokey_rust_core::runtime::Polling::new();

// Main loop only, including while neither transport owns a core session.
#[cfg(feature = "ctap")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_presence_sample() {
    unsafe {
        let poll = &mut *core::ptr::addr_of_mut!(PRESENCE);
        if let Some(on) = poll.sample(ck_platform_touched() != 0, ck_platform_now()) {
            ck_platform_led(u8::from(on));
        }
    }
}
impl Device for DeviceBackend {
    #[cfg(feature = "ctap")]
    fn wink(&mut self) {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(PRESENCE)).wink(ck_platform_now());
        }
    }
    #[cfg(feature = "ctap")]
    fn poll_presence(&mut self) -> bool {
        unsafe {
            let accepted = (&mut *core::ptr::addr_of_mut!(PRESENCE)).take(ck_platform_now());
            if accepted {
                ck_platform_led(0);
            }
            accepted
        }
    }
    fn keepalive(&mut self, waiting: bool) {
        #[cfg(feature = "ctap")]
        unsafe {
            ck_hid_keepalive(u8::from(waiting))
        };
        #[cfg(not(feature = "ctap"))]
        let _ = waiting;
    }
    fn serial(&mut self, out: &mut [u8; 4]) {
        #[cfg(feature = "platform-serial")]
        {
            unsafe { ck_platform_serial(out.as_mut_ptr()) }
        }
        #[cfg(not(feature = "platform-serial"))]
        {
            let _ = out;
        }
    }
    fn now(&mut self) -> u32 {
        #[cfg(feature = "platform-device")]
        {
            unsafe { ck_platform_now() }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            0
        }
    }
    fn touched(&mut self) -> bool {
        #[cfg(feature = "ctap")]
        unsafe {
            (&mut *core::ptr::addr_of_mut!(PRESENCE)).clear();
        }
        #[cfg(feature = "platform-device")]
        {
            unsafe { ck_platform_touched() != 0 }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            false
        }
    }
    fn progress(&mut self) -> bool {
        #[cfg(feature = "platform-device")]
        {
            unsafe { ck_platform_progress() != 0 }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            false
        }
    }
    fn led(&mut self, on: bool) {
        #[cfg(feature = "platform-device")]
        {
            unsafe { ck_platform_led(u8::from(on)) }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = on;
        }
    }
}
impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}
