// SPDX-License-Identifier: Apache-2.0
//! Device callbacks and volatile secret erasure adapter.
use crate::{Device, Memory};

/// Native platform capability, created only at the serialized FFI boundary.
/// The marker prevents transferring a borrowed hardware session across threads.
pub struct DeviceBackend(core::marker::PhantomData<*mut ()>);

impl DeviceBackend {
    /// # Safety
    /// All native platform access, including callbacks and other backend values,
    /// must remain serialized for this value's entire lifetime. Native global
    /// storage, crypto scratch and presence state are not independently locked.
    pub unsafe fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}
pub struct MemoryBackend;
#[cfg(feature = "device-runtime")]
unsafe extern "C" {
    fn ck_device_settings(flags: u32);
    fn ck_board_info(kind: u8, length: *mut usize) -> *const u8;
    fn ck_board_chip_id(output: *mut u8);
    fn ck_board_recovery_word() -> u32;
    #[cfg(feature = "platform-device")]
    fn ck_device_led_idle();
    #[cfg(feature = "platform-device")]
    fn ck_device_progress() -> u8;
}
#[cfg(feature = "platform-device")]
fn idle_led() {
    #[cfg(feature = "device-runtime")]
    unsafe {
        ck_device_led_idle();
    }
    #[cfg(not(feature = "device-runtime"))]
    unsafe {
        ck_platform_led(0);
    }
}

#[cfg(feature = "nfc")]
unsafe extern "C" {
    fn is_nfc() -> u8;
}

#[cfg(feature = "platform-device")]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    #[cfg(not(feature = "device-runtime"))]
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
}
#[cfg(feature = "platform-serial")]
unsafe extern "C" {
    #[cfg(not(feature = "device-runtime"))]
    fn ck_platform_serial(out: *mut u8);
    #[cfg(feature = "device-runtime")]
    fn ck_device_serial(out: *mut u8);
}
#[cfg(feature = "ctap")]
unsafe extern "C" {
    fn ck_hid_keepalive(waiting: u8);
}
#[cfg(feature = "ctap")]
static mut PRESENCE: crate::Polling = crate::Polling::new();

// Main loop only, including while neither transport owns a core session.
#[cfg(feature = "ctap")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_presence_sample() {
    #[cfg(feature = "nfc")]
    if unsafe { is_nfc() != 0 } {
        return;
    }
    unsafe {
        let poll = &mut *core::ptr::addr_of_mut!(PRESENCE);
        if let Some(on) = poll.sample(ck_platform_touched() != 0, ck_platform_now()) {
            if !poll.prompt_active() {
                idle_led();
            } else {
                ck_platform_led(u8::from(on));
            }
        }
    }
}
native_port! { impl Device for DeviceBackend {
    fn recovery_word(&mut self) -> Option<u32> {
        #[cfg(feature = "device-runtime")]
        { Some(unsafe {ck_board_recovery_word()}) }
        #[cfg(not(feature = "device-runtime"))]
        { None }
    }

    fn information(&mut self, kind: u8, output: &mut [u8]) -> usize {
        #[cfg(feature = "device-runtime")]
        {
            if kind == 3 {
                let mut id=[0;13];
                unsafe { ck_board_chip_id(id.as_mut_ptr()); }
                let len=output.len().min(id.len());output[..len].copy_from_slice(&id[..len]);
                return len;
            }
            let mut len=0;
            let data=unsafe { ck_board_info(kind,&mut len) };
            if data.is_null() { return 0; }
            let len=len.min(output.len());
            output[..len].copy_from_slice(unsafe {core::slice::from_raw_parts(data,len)});
            len
        }
        #[cfg(not(feature = "device-runtime"))]
        {
            let data: &[u8]=if kind==3 {&[0;13]} else {b"unknown"};
            let len=output.len().min(data.len());output[..len].copy_from_slice(&data[..len]);len
        }
    }

    fn configuration_changed(&mut self, flags: u32) {
        #[cfg(feature = "device-runtime")]
        unsafe { ck_device_settings(flags); }
        #[cfg(not(feature = "device-runtime"))]
        let _ = flags;
    }
    fn led_idle(&mut self) {
        #[cfg(feature = "platform-device")]
        idle_led();
    }
    fn contactless(&mut self) -> bool {
        #[cfg(feature = "nfc")]
        { unsafe { is_nfc() != 0 } }
        #[cfg(not(feature = "nfc"))]
        { false }
    }
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
                idle_led();
            }
            accepted
        }
    }
    fn keepalive(&mut self, waiting: bool) {
        #[cfg(feature = "nfc")]
        if unsafe { is_nfc() != 0 } { return; }
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
            #[cfg(feature = "device-runtime")]
            unsafe { ck_device_serial(out.as_mut_ptr()) }
            #[cfg(not(feature = "device-runtime"))]
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
            #[cfg(feature = "device-runtime")]
            { unsafe { ck_device_progress() != 0 } }
            #[cfg(not(feature = "device-runtime"))]
            { unsafe { ck_platform_progress() != 0 } }
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
}
impl MemoryBackend {
    #[inline(never)]
    pub fn wipe(&self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        MemoryBackend::wipe(self, bytes)
    }
}
