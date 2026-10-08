// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitive adapter. Policy and protocol stay in safe Rust.
use crate::{Crypto, CryptoError};

/// Native platform capability, created only at the serialized FFI boundary.
/// The marker prevents transferring a borrowed hardware session across threads.
pub struct CryptoBackend(core::marker::PhantomData<*mut ()>);

impl CryptoBackend {
    /// # Safety
    /// All native platform access, including callbacks and other backend values,
    /// must remain serialized for this value's entire lifetime. Native global
    /// storage, crypto scratch and presence state are not independently locked.
    pub unsafe fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

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
}
#[cfg(feature = "platform-random")]
unsafe extern "C" {
    fn ck_platform_random(out: *mut u8, len: usize) -> i32;
}
#[cfg(feature = "platform-stream")]
unsafe extern "C" {
    fn ck_digest_init(state: *mut crate::HashState) -> i32;
    fn ck_digest_update(state: *mut crate::HashState, input: *const u8, n: usize) -> i32;
    fn ck_digest_final(state: *mut crate::HashState, out: *mut u8, capacity: usize) -> i32;
    fn ck_digest_abort(state: *mut crate::HashState) -> i32;
}
#[cfg(feature = "platform-stream")]
unsafe extern "C" {
    fn ck_stream_abort(scratch: *mut crate::CryptoScratch);
    fn ck_stream_read(scratch: *mut crate::CryptoScratch, out: *mut u8, capacity: usize) -> i32;
    fn ck_stream_public_init(
        alg: u8,
        scratch: *mut crate::CryptoScratch,
        input: *const u8,
        n: usize,
    ) -> i32;
    fn ck_stream_sign_init(
        alg: u8,
        scratch: *mut crate::CryptoScratch,
        input: *const u8,
        n: usize,
    ) -> i32;
    fn ck_stream_sm2_identity(
        scratch: *mut crate::CryptoScratch,
        input: *const u8,
        n: usize,
    ) -> i32;
    fn ck_stream_sign_update(scratch: *mut crate::CryptoScratch, input: *const u8, n: usize)
    -> i32;
    fn ck_stream_sign_final(scratch: *mut crate::CryptoScratch) -> i32;
    fn ck_stream_decapsulate_init(
        alg: u8,
        scratch: *mut crate::CryptoScratch,
        input: *const u8,
        n: usize,
    ) -> i32;
    fn ck_stream_decapsulate_update(
        scratch: *mut crate::CryptoScratch,
        input: *const u8,
        n: usize,
    ) -> i32;
    fn ck_stream_decapsulate_final(
        scratch: *mut crate::CryptoScratch,
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
        key: *mut crate::KeyMaterial,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        capacity: usize,
    ) -> i32;
}
#[cfg(any(
    feature = "ctap",
    feature = "piv",
    feature = "platform-stream",
    feature = "platform-mac",
    feature = "platform-random"
))]
fn rc_unit(n: i32) -> Result<(), CryptoError> {
    if n == 0 {
        Ok(())
    } else {
        Err(CryptoError::Failure)
    }
}

#[cfg(any(feature = "platform-stream", feature = "platform-key"))]
fn rc_len(n: i32, capacity: usize) -> Result<usize, CryptoError> {
    if n < 0 || n as usize > capacity {
        Err(CryptoError::Failure)
    } else {
        Ok(n as usize)
    }
}

impl Crypto for CryptoBackend {
    #[cfg(feature = "ctap")]
    fn p256_sign(
        &mut self,
        scalar: &[u8; 32],
        digest: &[u8; 32],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        rc_unit(unsafe {
            ck_platform_p256_sign(scalar.as_ptr(), digest.as_ptr(), out.as_mut_ptr())
        })
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
        rc_unit(unsafe {
            ck_platform_aes256(
                u8::from(encrypt),
                key.as_ptr(),
                iv.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
            )
        })
    }

    #[cfg(feature = "platform-stream")]
    fn digest(
        &mut self,
        op: crate::DigestOperation,
        state: &mut crate::HashState,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        rc_unit(unsafe {
            match op {
                crate::DigestOperation::Init => ck_digest_init(state),
                crate::DigestOperation::Update => {
                    ck_digest_update(state, input.as_ptr(), input.len())
                }
                crate::DigestOperation::Final => {
                    ck_digest_final(state, out.as_mut_ptr(), out.len())
                }
                crate::DigestOperation::Abort => ck_digest_abort(state),
            }
        })
    }
    #[cfg(feature = "platform-stream")]
    fn stream(
        &mut self,
        op: crate::StreamOperation,
        alg: u8,
        scratch: &mut crate::CryptoScratch,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = unsafe {
            match op {
                crate::StreamOperation::Abort => {
                    ck_stream_abort(scratch);
                    0
                }
                crate::StreamOperation::Read => {
                    ck_stream_read(scratch, out.as_mut_ptr(), out.len())
                }
                crate::StreamOperation::PublicInit => {
                    ck_stream_public_init(alg, scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::SignInit => {
                    ck_stream_sign_init(alg, scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::Sm2Identity => {
                    ck_stream_sm2_identity(scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::SignUpdate => {
                    ck_stream_sign_update(scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::SignFinal => ck_stream_sign_final(scratch),
                crate::StreamOperation::DecapsulateInit => {
                    ck_stream_decapsulate_init(alg, scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::DecapsulateUpdate => {
                    ck_stream_decapsulate_update(scratch, input.as_ptr(), input.len())
                }
                crate::StreamOperation::DecapsulateFinal => {
                    ck_stream_decapsulate_final(scratch, out.as_mut_ptr(), out.len())
                }
            }
        };
        rc_len(n, usize::MAX)
    }

    #[cfg(feature = "piv")]
    fn aes192(
        &mut self,
        key: &[u8; 24],
        input: &[u8; 16],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        rc_unit(unsafe { ck_platform_aes192(key.as_ptr(), input.as_ptr(), out.as_mut_ptr()) })
    }

    #[cfg(feature = "platform-key")]
    fn key_operation(
        &mut self,
        op: crate::KeyOperation,
        algorithm: u8,
        key: &mut crate::KeyMaterial,
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
        if n == -2 && matches!(op, crate::KeyOperation::RsaPkcs1Decipher) {
            // CK_KEY_INVALID_PADDING in crypto_ops.h.
            Err(CryptoError::InvalidPadding)
        } else {
            rc_len(n, out.len())
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
            rc_unit(unsafe {
                ck_platform_mac(
                    algorithm,
                    key.as_ptr(),
                    key.len(),
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                )
            })
        }
        #[cfg(not(feature = "platform-mac"))]
        {
            let _ = (algorithm, key, input, out);
            Err(CryptoError::Failure)
        }
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(feature = "platform-random")]
        {
            rc_unit(unsafe { ck_platform_random(out.as_mut_ptr(), out.len()) })
        }
        #[cfg(not(feature = "platform-random"))]
        {
            let _ = out;
            Err(CryptoError::Failure)
        }
    }
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        #[cfg(feature = "platform-hmac")]
        unsafe {
            ck_platform_hmac_sha1(key.as_ptr(), input.as_ptr(), input.len(), out.as_mut_ptr());
        }
        #[cfg(not(feature = "platform-hmac"))]
        {
            // Without a provider this infallible ABI leaves output untouched.
            // Callers needing a digest must enable platform-hmac; there is no
            // failure return value as there is for mac/random.
            let _ = (key, input, out);
        }
    }
}
