// SPDX-License-Identifier: Apache-2.0
//! Test bridge for the C fixtures' native key and stream buffers.
use canokey_native_crypto::CryptoBackend;
use canokey_ports::{Crypto, KeyMaterial, KeyOperation};

/// # Safety
/// Key must be an aligned, exclusive KeyMaterial. The fixture supplies
/// disjoint input and output buffers and serializes native calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_test_key(
    op: u8,
    algorithm: u8,
    key: *mut KeyMaterial,
    input: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    use KeyOperation::*;
    let operations = [
        Generate,
        Validate,
        Public,
        RsaPkcs1Sign,
        RsaPkcs1Decipher,
        Agree,
        EcSign,
        RsaRaw,
        Sm2Exchange,
        Sm2MessageDigest,
    ];
    let Some(op) = operations
        .into_iter()
        .find(|&operation| operation as u8 == op)
    else {
        return -1;
    };
    unsafe {
        let input = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(input, len)
        };
        let out = if capacity == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(out, capacity)
        };
        CryptoBackend::new()
            .key_operation(op, algorithm, &mut *key, input, out)
            .map_or(-1, |n| n as i32)
    }
}

#[cfg(feature = "platform-stream")]
mod stream {
    use super::*;
    use canokey_ports::{CryptoScratch, StreamOperation};

    /// # Safety
    /// Scratch and the input and output ranges are aligned and disjoint.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ck_test_stream(
        op: u8,
        algorithm: u8,
        scratch: *mut CryptoScratch,
        input: *const u8,
        len: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32 {
        use StreamOperation::*;
        let operations = [
            PublicInit,
            Read,
            SignInit,
            SignUpdate,
            SignFinal,
            Abort,
            DecapsulateInit,
            DecapsulateUpdate,
            DecapsulateFinal,
            Sm2Identity,
        ];
        let Some(op) = operations
            .into_iter()
            .find(|&operation| operation as u8 == op)
        else {
            return -1;
        };
        unsafe {
            let input = if len == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(input, len)
            };
            let out = if capacity == 0 {
                &mut []
            } else {
                core::slice::from_raw_parts_mut(out, capacity)
            };
            CryptoBackend::new()
                .stream(op, algorithm, &mut *scratch, input, out)
                .map_or(-1, |n| n as i32)
        }
    }

    #[cfg(feature = "ctap")]
    /// # Safety
    /// Scratch must be an aligned, exclusive CryptoScratch.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ck_test_rewind_public(scratch: *mut CryptoScratch) -> i32 {
        if unsafe { CryptoBackend::new().rewind_public(&mut *scratch) } {
            0
        } else {
            -1
        }
    }
}
