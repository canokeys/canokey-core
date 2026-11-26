// SPDX-License-Identifier: Apache-2.0
use KeyOperation::*;
use canokey_ports::{CryptoError, KeyMaterial, KeyOperation, RSA_OUTPUT_BYTES, alg};

unsafe extern "C" {
    fn ck_key_ec_generate(alg: u8, key: *mut KeyMaterial) -> i32;
    fn ck_key_ec_validate(alg: u8, key: *mut KeyMaterial) -> i32;
    fn ck_key_ec_public(alg: u8, key: *mut KeyMaterial, out: *mut u8) -> i32;
    fn ck_key_ec_sign(
        alg: u8,
        key: *mut KeyMaterial,
        input: *const u8,
        len: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn ck_key_ec_agree(
        alg: u8,
        key: *mut KeyMaterial,
        input: *const u8,
        len: usize,
        out: *mut u8,
    ) -> i32;
    #[cfg(any(feature = "ctap", feature = "piv"))]
    fn ck_sm2_message_digest(key: *mut u8, input: *const u8, len: usize, out: *mut u8) -> i32;
    #[cfg(feature = "piv")]
    fn ck_sm2_exchange(key: *mut u8, input: *const u8, len: usize, out: *mut u8) -> i32;
    #[cfg(feature = "stack-report")]
    fn ck_stack_context(op: u8, alg: u8);
}

pub(super) fn operate(
    op: KeyOperation,
    algorithm: u8,
    key: &mut KeyMaterial,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if algorithm > alg::SM2 || (out.len() < RSA_OUTPUT_BYTES && !matches!(op, EcSign)) {
        return Err(CryptoError::Failure);
    }
    #[cfg(feature = "stack-report")]
    unsafe {
        ck_stack_context(op as u8, algorithm)
    };
    if (alg::RSA2048..=alg::RSA4096).contains(&algorithm) {
        #[cfg(feature = "platform-rsa")]
        if out.len() >= RSA_OUTPUT_BYTES {
            return rsa::operate(op, algorithm, key, input, out);
        }
        return Err(CryptoError::Failure);
    }
    if (!cfg!(feature = "platform-x25519") && algorithm == alg::X25519)
        || (!cfg!(any(feature = "ctap", feature = "piv")) && algorithm == alg::SM2)
    {
        return Err(CryptoError::Failure);
    }
    // SAFETY: the native adapters check KeyMaterial's layout at compile time.
    // The generic output reservation covers every result except EcSign, whose
    // primitive checks the algorithm-specific capacity before writing.
    let n = unsafe {
        match op {
            Generate => ck_key_ec_generate(algorithm, key),
            Validate => ck_key_ec_validate(algorithm, key),
            Public => ck_key_ec_public(algorithm, key, out.as_mut_ptr()),
            EcSign => ck_key_ec_sign(
                algorithm,
                key,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
            ),
            Agree => ck_key_ec_agree(
                algorithm,
                key,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
            ),
            #[cfg(any(feature = "ctap", feature = "piv"))]
            Sm2MessageDigest if algorithm == alg::SM2 => ck_sm2_message_digest(
                key.bytes.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
            ),
            #[cfg(feature = "piv")]
            Sm2Exchange if algorithm == alg::SM2 => ck_sm2_exchange(
                key.bytes.as_mut_ptr(),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
            ),
            _ => return Err(CryptoError::Failure),
        }
    };
    // A negative status casts above the maximum length of a Rust slice.
    if n as usize > out.len() {
        Err(CryptoError::Failure)
    } else {
        Ok(n as usize)
    }
}

#[cfg(feature = "platform-rsa")]
mod rsa {
    use super::*;

    unsafe extern "C" {
        fn rsa_generate_key(key: *mut KeyMaterial, bits: u16) -> i32;
        fn rsa_check_crt_with_scratch(
            key: *const KeyMaterial,
            scratch: *mut u8,
            capacity: usize,
        ) -> i32;
        fn rsa_get_public_key(key: *mut KeyMaterial, out: *mut u8) -> i32;
        fn rsa_private(key: *const KeyMaterial, input: *const u8, out: *mut u8) -> i32;
        fn rsa_sign_pkcs_v15(
            key: *const KeyMaterial,
            input: *const u8,
            len: usize,
            out: *mut u8,
        ) -> i32;
        fn rsa_decrypt_pkcs_v15(
            key: *const KeyMaterial,
            input: *const u8,
            len: *mut usize,
            out: *mut u8,
            invalid: *mut u8,
        ) -> i32;
    }

    #[inline(never)]
    pub(super) fn operate(
        op: KeyOperation,
        algorithm: u8,
        key: &mut KeyMaterial,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        const MIN_BITS: u16 = 2048;
        const BITS_STEP: u16 = 1024;
        // RFC 8017 requires at least 11 octets of PKCS#1 v1.5 overhead.
        const PKCS1_OVERHEAD: usize = 11;

        key.bits = MIN_BITS + BITS_STEP * u16::from(algorithm - alg::RSA2048);
        let width = usize::from(key.bits) / 8;
        let mut written = width;
        let output = out.as_mut_ptr();
        // SAFETY: the caller validates the RSA selector and reserves a full
        // modulus of output. Fixed-width inputs are checked before FFI.
        let status = unsafe {
            match op {
                Generate => {
                    written = 0;
                    rsa_generate_key(key, key.bits)
                }
                Validate => {
                    written = 0;
                    rsa_check_crt_with_scratch(key, output, RSA_OUTPUT_BYTES)
                }
                Public => rsa_get_public_key(key, output),
                RsaRaw if input.len() == width => rsa_private(key, input.as_ptr(), output),
                RsaPkcs1Sign if input.len() <= width - PKCS1_OVERHEAD => {
                    rsa_sign_pkcs_v15(key, input.as_ptr(), input.len(), output)
                }
                RsaPkcs1Decipher if input.len() == width => {
                    let mut invalid = 0;
                    written = 0;
                    let status = rsa_decrypt_pkcs_v15(
                        key,
                        input.as_ptr(),
                        &mut written,
                        output,
                        &mut invalid,
                    );
                    if invalid != 0 {
                        return Err(CryptoError::InvalidPadding);
                    }
                    status
                }
                _ => return Err(CryptoError::Failure),
            }
        };
        super::super::rc_unit(status)?;
        if written > width {
            return Err(CryptoError::Failure);
        }
        Ok(written)
    }
}
