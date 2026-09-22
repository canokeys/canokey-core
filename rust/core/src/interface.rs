// SPDX-License-Identifier: Apache-2.0
//! All entrypoints and callbacks must be serialized, non-reentrant and called
//! from the main loop. Pointers must cover the stated lengths. RX/TX may alias.
use crate::{Core, Platform};
static mut CORE: Core = Core::new();
struct Services;
#[cfg(feature = "pass")]
unsafe extern "C" {
    fn ck_platform_size(file: u8) -> i32;
    fn ck_platform_read(file: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(file: u8, input: *const u8, len: usize) -> i32;
    fn ck_platform_sha256(input: *const u8, len: usize, out: *mut u8);
    fn ck_platform_hmac_sha1(key: *const u8, input: *const u8, len: usize, out: *mut u8);
}
impl Platform for Services {
    fn size(&mut self, file: u8) -> i32 {
        #[cfg(feature = "pass")]
        {
            unsafe { ck_platform_size(file) }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = file;
            -1
        }
    }
    fn read(&mut self, file: u8, out: &mut [u8]) -> i32 {
        #[cfg(feature = "pass")]
        {
            unsafe { ck_platform_read(file, out.as_mut_ptr(), out.len()) }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (file, out);
            -1
        }
    }
    fn write(&mut self, file: u8, input: &[u8]) -> i32 {
        #[cfg(feature = "pass")]
        {
            unsafe { ck_platform_write(file, input.as_ptr(), input.len()) }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (file, input);
            -1
        }
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) {
        #[cfg(feature = "pass")]
        unsafe {
            ck_platform_sha256(input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (input, out);
        }
    }
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        #[cfg(feature = "pass")]
        unsafe {
            ck_platform_hmac_sha1(key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (key, input, out);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_install() -> i32 {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE))
            .install(&mut Services)
            .map_or(-1, |_| 0)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_reset() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE)).reset(&mut Services);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ck_core_applet_count() -> u8 {
    Core::applet_count()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_exchange(
    owner: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    if input.is_null()
        || out.is_null()
        || len > isize::MAX as usize
        || capacity > isize::MAX as usize
        || capacity < 2
    {
        return -1;
    }
    unsafe {
        let engine = &mut *core::ptr::addr_of_mut!(CORE);
        let reply = engine.receive(
            owner,
            core::slice::from_raw_parts(input, len),
            &mut Services,
        );
        engine
            .transmit(reply, core::slice::from_raw_parts_mut(out, capacity))
            .map_or(-1, |n| n as i32)
    }
}
#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_touch(index: u8, out: *mut u8, capacity: usize) -> i32 {
    if out.is_null() || capacity > isize::MAX as usize {
        return -1;
    }
    unsafe {
        (&*core::ptr::addr_of!(CORE))
            .touch(
                index,
                core::slice::from_raw_parts_mut(out, capacity),
                &mut Services,
            )
            .map_or(-1, |n| n as i32)
    }
}
#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_challenge(
    index: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    if input.is_null() || out.is_null() || len > 64 {
        return -1;
    }
    unsafe {
        let mut result = [0; 20];
        let status = (&*core::ptr::addr_of!(CORE)).challenge(
            index,
            core::slice::from_raw_parts(input, len),
            &mut result,
            &mut Services,
        );
        if status.is_ok() {
            core::ptr::copy_nonoverlapping(result.as_ptr(), out, 20);
        }
        Services.wipe(&mut result);
        status.map_or(-1, |_| 0)
    }
}
