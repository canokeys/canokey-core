// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitive adapter. Policy and protocol stay in safe Rust.
use canokey_rust_core::ports::{Crypto, CryptoError};

pub(super) struct CryptoBackend;

#[cfg(any(
    feature = "admin",
    feature = "pass",
    feature = "oath",
    feature = "openpgp",
    feature = "piv"
))]
unsafe extern "C" {
    fn ck_platform_hmac_sha1(key: *const u8, input: *const u8, len: usize, out: *mut u8);
}
#[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
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
#[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
unsafe extern "C" {
    #[cfg(any(feature = "openpgp", feature = "piv"))]
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
