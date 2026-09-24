// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitive adapter. Policy and protocol stay in safe Rust.
use canokey_rust_core::ports::{Crypto, CryptoError};

pub(super) struct CryptoBackend;

#[cfg(feature = "platform-hmac")]
unsafe extern "C" {
    fn ck_platform_hmac_sha1(key: *const u8, input: *const u8, len: usize, out: *mut u8);
}
#[cfg(feature = "platform-mac")]
unsafe extern "C" {
    fn ck_platform_mac(
        algorithm: u8,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        len: usize,
        out: *mut u8,
    ) -> i32;
    fn ck_platform_random(out: *mut u8, len: usize) -> i32;
}
#[cfg(feature = "platform-stream")]
unsafe extern "C" {
    fn ck_platform_digest(
        op: u8,
        state: *mut canokey_rust_core::ports::HashState,
        input: *const u8,
        n: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
}
#[cfg(feature = "platform-stream")]
unsafe extern "C" {
    fn ck_platform_stream(
        op: u8,
        alg: u8,
        scratch: *mut canokey_rust_core::ports::CryptoScratch,
        input: *const u8,
        n: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    #[cfg(feature = "piv")]
    fn ck_platform_aes192(key: *const u8, input: *const u8, out: *mut u8) -> i32;
}
#[cfg(feature = "ctap")]
unsafe extern "C" {
    fn ck_platform_p256_sign(scalar: *const u8, digest: *const u8, out: *mut u8) -> i32;
    fn ck_platform_sha256(input: *const u8, length: usize, out: *mut u8);
    fn ck_platform_aes256(
        encrypt: u8,
        key: *const u8,
        iv: *const u8,
        data: *mut u8,
        length: usize,
    ) -> i32;
}
#[cfg(feature = "platform-key")]
unsafe extern "C" {
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
impl Crypto for CryptoBackend {
    #[cfg(feature = "ctap")]
    fn p256_sign(
        &mut self,
        scalar: &[u8; 32],
        digest: &[u8; 32],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        if unsafe { ck_platform_p256_sign(scalar.as_ptr(), digest.as_ptr(), out.as_mut_ptr()) } == 0
        {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }

    #[cfg(feature = "ctap")]
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        unsafe {
            ck_platform_sha256(input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        Ok(())
    }
    #[cfg(feature = "ctap")]
    fn aes256_cbc(
        &mut self,
        encrypt: bool,
        key: &[u8; 32],
        iv: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        if unsafe {
            ck_platform_aes256(
                u8::from(encrypt),
                key.as_ptr(),
                iv.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }

    #[cfg(feature = "platform-stream")]
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
    #[cfg(feature = "platform-stream")]
    fn stream(
        &mut self,
        op: canokey_rust_core::ports::StreamOperation,
        alg: u8,
        scratch: &mut canokey_rust_core::ports::CryptoScratch,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = unsafe {
            ck_platform_stream(
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

    #[cfg(feature = "platform-key")]
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
        #[cfg(feature = "platform-mac")]
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
        #[cfg(not(feature = "platform-mac"))]
        {
            let _ = (algorithm, key, input, out);
            Err(CryptoError)
        }
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(feature = "platform-mac")]
        {
            if unsafe { ck_platform_random(out.as_mut_ptr(), out.len()) } == 0 {
                Ok(())
            } else {
                Err(CryptoError)
            }
        }
        #[cfg(not(feature = "platform-mac"))]
        {
            let _ = out;
            Err(CryptoError)
        }
    }
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        #[cfg(feature = "platform-hmac")]
        unsafe {
            ck_platform_hmac_sha1(key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        #[cfg(not(feature = "platform-hmac"))]
        {
            let _ = (key, input, out);
        }
    }
}
