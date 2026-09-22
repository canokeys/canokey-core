// SPDX-License-Identifier: Apache-2.0
//! Main-loop only, serialized, non-reentrant C boundary. RX/TX may alias.
use crate::{
    Core,
    services::{Record, Secrets, Storage, StorageError},
};
static mut CORE: Core = Core::new();
struct Services;
#[cfg(feature = "pass")]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
    fn ck_platform_read(file: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(file: u8, input: *const u8, len: usize) -> i32;
    fn ck_platform_hmac_sha1(key: *const u8, input: *const u8, len: usize, out: *mut u8);
}
#[cfg(feature = "oath")]
unsafe extern "C" {
    fn ck_platform_size(file: u8) -> i32;
    fn ck_platform_read_at(file: u8, offset: u32, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write_at(file: u8, offset: u32, input: *const u8, len: usize) -> i32;
    fn ck_platform_has_space(bytes: u32, reserve: u32) -> i32;
    fn ck_platform_mac(
        algorithm: u8,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        len: usize,
        out: *mut u8,
    ) -> i32;
    fn ck_platform_random(out: *mut u8, len: usize) -> i32;
    fn ck_platform_serial(out: *mut u8);
}
impl Storage for Services {
    #[cfg(feature = "oath")]
    fn size(&mut self, file: Record) -> Result<u32, StorageError> {
        match unsafe { ck_platform_size(file as u8) } {
            -1 => Err(StorageError::Missing),
            n if n >= 0 => Ok(n as u32),
            _ => Err(StorageError::Unavailable),
        }
    }
    #[cfg(feature = "oath")]
    fn read_at(&mut self, file: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_read_at(file as u8, offset, out.as_mut_ptr(), out.len()) }
            == out.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(feature = "oath")]
    fn replace_at(&mut self, file: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_write_at(file as u8, offset, input.as_ptr(), input.len()) }
            == input.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(feature = "oath")]
    fn has_space(&mut self, bytes: u32, reserve: u32) -> Result<bool, StorageError> {
        match unsafe { ck_platform_has_space(bytes, reserve) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StorageError::Unavailable),
        }
    }

    fn load(&mut self, file: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        #[cfg(feature = "pass")]
        {
            match unsafe { ck_platform_read(file as u8, out.as_mut_ptr(), out.len()) } {
                -1 => Err(StorageError::Missing),
                n if n >= 0 => Ok(n as usize),
                _ => Err(StorageError::Unavailable),
            }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (file, out);
            Err(StorageError::Unavailable)
        }
    }
    fn replace(&mut self, file: Record, input: &[u8]) -> Result<(), StorageError> {
        #[cfg(feature = "pass")]
        {
            if unsafe { ck_platform_write(file as u8, input.as_ptr(), input.len()) }
                == input.len() as i32
            {
                Ok(())
            } else {
                Err(StorageError::Uncertain)
            }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = (file, input);
            Err(StorageError::Unavailable)
        }
    }
}
impl Secrets for Services {
    #[cfg(feature = "oath")]
    fn mac(
        &mut self,
        algorithm: u8,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), StorageError> {
        if unsafe {
            ck_platform_mac(
                algorithm,
                key.as_ptr(),
                key.len(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(feature = "oath")]
    fn random(&mut self, out: &mut [u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_random(out.as_mut_ptr(), out.len()) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(feature = "oath")]
    fn serial(&mut self, out: &mut [u8; 4]) {
        unsafe { ck_platform_serial(out.as_mut_ptr()) }
    }
    #[cfg(feature = "pass")]
    fn now(&mut self) -> u32 {
        unsafe { ck_platform_now() }
    }
    #[cfg(feature = "pass")]
    fn touched(&mut self) -> bool {
        unsafe { ck_platform_touched() != 0 }
    }
    #[cfg(feature = "pass")]
    fn progress(&mut self) -> bool {
        unsafe { ck_platform_progress() != 0 }
    }

    #[cfg(feature = "pass")]
    fn led(&mut self, on: bool) {
        unsafe { ck_platform_led(u8::from(on)) }
    }

    fn wipe(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
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

#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_output_sample(pressed: u8, now: u32, ready: u8) -> i32 {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE))
            .sample_output(pressed != 0, now, ready != 0, &mut Services)
            .map_or(-1, i32::from)
    }
}
