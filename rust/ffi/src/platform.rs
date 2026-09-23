// SPDX-License-Identifier: Apache-2.0
//! Serialized low-level C services; no applet dispatch or record interpretation.
use canokey_rust_core::ports::{
    Crypto, CryptoError, Device, Memory, Platform, Record, Storage, StorageError,
};
struct StorageBackend;
struct CryptoBackend;
struct DeviceBackend;
struct MemoryBackend;
pub(crate) fn with_platform<T>(run: impl FnOnce(&mut Platform<'_>) -> T) -> T {
    run(&mut Platform {
        storage: &mut StorageBackend,
        crypto: &mut CryptoBackend,
        device: &mut DeviceBackend,
        memory: &MemoryBackend,
    })
}
#[cfg(any(
    feature = "admin",
    feature = "pass",
    feature = "oath",
    feature = "openpgp",
    feature = "piv"
))]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
    fn ck_platform_read(file: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(file: u8, input: *const u8, len: usize) -> i32;
    fn ck_platform_hmac_sha1(key: *const u8, input: *const u8, len: usize, out: *mut u8);
}
#[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
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
impl Storage for StorageBackend {
    #[cfg(feature = "piv")]
    fn remove(&mut self, id: Record) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(4, id as u8, core::ptr::null(), 0) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(feature = "piv")]
    fn move_record(&mut self, from: Record, to: Record) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(5, from as u8, &(to as u8), 1) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }

    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(0, 0, core::ptr::null(), 0) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_append(&mut self, b: &[u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(1, 0, b.as_ptr(), b.len()) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_commit(&mut self, id: Record) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(2, id as u8, core::ptr::null(), 0) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_abort(&mut self) {
        unsafe {
            ck_platform_stage(3, 0, core::ptr::null(), 0);
        }
    }

    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn size(&mut self, file: Record) -> Result<u32, StorageError> {
        match unsafe { ck_platform_size(file as u8) } {
            -1 => Err(StorageError::Missing),
            n if n >= 0 => Ok(n as u32),
            _ => Err(StorageError::Unavailable),
        }
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn read_at(&mut self, file: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_read_at(file as u8, offset, out.as_mut_ptr(), out.len()) }
            == out.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn replace_at(&mut self, file: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_write_at(file as u8, offset, input.as_ptr(), input.len()) }
            == input.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    fn has_space(&mut self, bytes: u32, reserve: u32) -> Result<bool, StorageError> {
        match unsafe { ck_platform_has_space(bytes, reserve) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StorageError::Unavailable),
        }
    }

    fn load(&mut self, file: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            match unsafe { ck_platform_read(file as u8, out.as_mut_ptr(), out.len()) } {
                -1 => Err(StorageError::Missing),
                n if n >= 0 => Ok(n as usize),
                _ => Err(StorageError::Unavailable),
            }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = (file, out);
            Err(StorageError::Unavailable)
        }
    }
    fn replace(&mut self, file: Record, input: &[u8]) -> Result<(), StorageError> {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            if unsafe { ck_platform_write(file as u8, input.as_ptr(), input.len()) }
                == input.len() as i32
            {
                Ok(())
            } else {
                Err(StorageError::Uncertain)
            }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = (file, input);
            Err(StorageError::Unavailable)
        }
    }
}
#[cfg(feature = "piv")]
unsafe extern "C" {
    fn ck_platform_digest(
        op: u8,
        state: *mut canokey_rust_core::ports::HashState,
        input: *const u8,
        n: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn ck_platform_piv_stream(
        op: u8,
        alg: u8,
        scratch: *mut canokey_rust_core::ports::CryptoScratch,
        input: *const u8,
        n: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn ck_platform_aes192(key: *const u8, input: *const u8, out: *mut u8) -> i32;
}
impl Crypto for CryptoBackend {
    #[cfg(feature = "piv")]
    fn digest(
        &mut self,
        op: canokey_rust_core::ports::DigestOperation,
        state: &mut canokey_rust_core::ports::HashState,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if unsafe {
            ck_platform_digest(
                op as u8,
                state,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
    #[cfg(feature = "piv")]
    fn piv_stream(
        &mut self,
        op: canokey_rust_core::ports::StreamOperation,
        alg: u8,
        scratch: &mut canokey_rust_core::ports::CryptoScratch,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = unsafe {
            ck_platform_piv_stream(
                op as u8,
                alg,
                scratch,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        if n < 0 {
            Err(CryptoError)
        } else {
            Ok(n as usize)
        }
    }

    #[cfg(feature = "piv")]
    fn aes192(
        &mut self,
        key: &[u8; 24],
        input: &[u8; 16],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        if unsafe { ck_platform_aes192(key.as_ptr(), input.as_ptr(), out.as_mut_ptr()) } == 0 {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }

    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn key_operation(
        &mut self,
        op: canokey_rust_core::ports::KeyOperation,
        algorithm: u8,
        key: &mut canokey_rust_core::ports::KeyMaterial,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = unsafe {
            ck_platform_key(
                op as u8,
                algorithm,
                key,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        if n < 0 || n as usize > out.len() {
            Err(CryptoError)
        } else {
            Ok(n as usize)
        }
    }

    fn mac(
        &mut self,
        algorithm: u8,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
        {
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
                Err(CryptoError)
            }
        }
        #[cfg(not(any(feature = "oath", feature = "openpgp", feature = "piv")))]
        {
            let _ = (algorithm, key, input, out);
            Err(CryptoError)
        }
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
        {
            if unsafe { ck_platform_random(out.as_mut_ptr(), out.len()) } == 0 {
                Ok(())
            } else {
                Err(CryptoError)
            }
        }
        #[cfg(not(any(feature = "oath", feature = "openpgp", feature = "piv")))]
        {
            let _ = out;
            Err(CryptoError)
        }
    }
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        unsafe {
            ck_platform_hmac_sha1(key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = (key, input, out);
        }
    }
}
impl Device for DeviceBackend {
    fn serial(&mut self, out: &mut [u8; 4]) {
        #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
        {
            unsafe { ck_platform_serial(out.as_mut_ptr()) }
        }
        #[cfg(not(any(feature = "oath", feature = "openpgp", feature = "piv")))]
        {
            let _ = out;
        }
    }
    fn now(&mut self) -> u32 {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_now() }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            0
        }
    }
    fn touched(&mut self) -> bool {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_touched() != 0 }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            false
        }
    }
    fn progress(&mut self) -> bool {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_progress() != 0 }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
        {
            let _ = ();
            false
        }
    }
    fn led(&mut self, on: bool) {
        #[cfg(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        ))]
        {
            unsafe { ck_platform_led(u8::from(on)) }
        }
        #[cfg(not(any(
            feature = "admin",
            feature = "pass",
            feature = "oath",
            feature = "openpgp",
            feature = "piv"
        )))]
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

#[cfg(any(feature = "openpgp", feature = "piv"))]
unsafe extern "C" {
    fn ck_platform_stage(operation: u8, file: u8, input: *const u8, len: usize) -> i32;
    fn ck_platform_key(
        operation: u8,
        algorithm: u8,
        key: *mut canokey_rust_core::ports::KeyMaterial,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        capacity: usize,
    ) -> i32;
}
