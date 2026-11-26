// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "piv")]
use canokey_ports::mlkem;
use canokey_ports::{
    CRYPTO_SCRATCH_BYTES, CryptoError, CryptoScratch, STREAM_DATA_ALIGN, STREAM_DATA_BYTES,
    StreamOperation, alg, mldsa,
};

const PUBLIC: u8 = 0x01;
const SIGNING: u8 = 0x02;
const SIGNATURE: u8 = 0x03;
#[cfg(feature = "piv")]
const DECAPSULATING: u8 = 0x04;
const CLASSIC_SEED_BYTES: usize = 32;
const CLASSIC_SIGNATURE_BYTES: usize = 64;
const SM2_ID_MAX_BYTES: usize = 32;

#[repr(C)]
struct State {
    kind: u8,
    alg: u8,
    remaining: u16,
    position: u16,
    length: u16,
}

const _: () = {
    assert!(core::mem::align_of::<CryptoScratch>() == STREAM_DATA_ALIGN);
    assert!(STREAM_DATA_BYTES % core::mem::align_of::<State>() == 0);
    assert!(STREAM_DATA_BYTES + core::mem::size_of::<State>() <= CRYPTO_SCRATCH_BYTES);
};

unsafe extern "C" {
    fn ck_stream_abort(data: *mut u8, alg: u8, signature: u8);
    fn ck_stream_output(data: *const u8, alg: u8, signature: u8) -> *const u8;
    fn ck_stream_refill(data: *mut u8, alg: u8, remaining: usize) -> i32;
    fn ck_stream_public_init(alg: u8, data: *mut u8, seed: *const u8) -> i32;
    fn ck_stream_sign_init(alg: u8, data: *mut u8, seed: *const u8) -> i32;
    fn ck_stream_sm2_identity(data: *mut u8, input: *const u8, n: usize) -> i32;
    fn ck_stream_sign_update(data: *mut u8, alg: u8, input: *const u8, n: usize) -> i32;
    fn ck_stream_sign_final(data: *mut u8, alg: u8, total: usize) -> i32;
    #[cfg(feature = "piv")]
    fn ck_stream_decapsulate_init(data: *mut u8, seed: *const u8);
    #[cfg(feature = "piv")]
    fn ck_stream_decapsulate_update(data: *mut u8, offset: usize, input: *const u8, n: usize);
    #[cfg(feature = "piv")]
    fn ck_stream_decapsulate_final(data: *mut u8, alg: u8, out: *mut u8) -> i32;
}

fn parts(scratch: &mut CryptoScratch) -> (*mut u8, &mut State) {
    let data = scratch.as_mut_ptr();
    // SAFETY: the assertions above bound and align State, and all fields accept
    // every bit pattern. The native union is confined to the disjoint prefix.
    (data, unsafe {
        &mut *data.add(STREAM_DATA_BYTES).cast::<State>()
    })
}

impl State {
    fn begin(&mut self, kind: u8, alg: u8, total: usize) {
        *self = Self {
            kind,
            alg,
            remaining: total as u16,
            position: 0,
            length: 0,
        };
    }

    fn abort(&mut self, data: *mut u8) {
        unsafe { ck_stream_abort(data, self.alg, u8::from(self.kind == SIGNATURE)) };
        self.begin(0, 0, 0);
    }

    fn read(&mut self, data: *mut u8, out: &mut [u8]) -> Result<usize, CryptoError> {
        if (self.kind != PUBLIC && self.kind != SIGNATURE)
            || out.len() > usize::from(self.remaining)
        {
            return Err(CryptoError::Failure);
        }

        let signature = u8::from(self.kind == SIGNATURE);
        let source = unsafe { ck_stream_output(data, self.alg, signature) };
        let mut written = 0;
        while written < out.len() {
            if self.position == self.length {
                let length = unsafe { ck_stream_refill(data, self.alg, self.remaining.into()) };
                if length < 0 {
                    return Err(CryptoError::Failure);
                }
                self.length = length as u16;
                self.position = 0;
            }
            let count = usize::from(self.length - self.position).min(out.len() - written);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.add(self.position.into()),
                    out.as_mut_ptr().add(written),
                    count,
                );
            }
            self.position += count as u16;
            self.remaining -= count as u16;
            written += count;
        }
        Ok(written)
    }
}

pub(super) fn operate(
    op: StreamOperation,
    alg: u8,
    scratch: &mut CryptoScratch,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    use StreamOperation::*;
    let (data, state) = parts(scratch);
    // SAFETY: operation guards establish the active union member before use.
    // Seed and output parameters are checked before invoking their primitives.
    unsafe {
        match op {
            Abort => state.abort(data),
            Read => return state.read(data, out),
            PublicInit => {
                let total = if let Some(params) =
                    mldsa::parameters(alg).filter(|_| input.len() == mldsa::SEED_BYTES)
                {
                    params.public_bytes
                } else {
                    #[cfg(feature = "piv")]
                    {
                        mlkem::parameters(alg)
                            .filter(|_| input.len() == mlkem::SEED_BYTES)
                            .ok_or(CryptoError::Failure)?
                            .public_bytes
                    }
                    #[cfg(not(feature = "piv"))]
                    return Err(CryptoError::Failure);
                };
                state.abort(data);
                if ck_stream_public_init(alg, data, input.as_ptr()) != 0 {
                    state.abort(data);
                    return Err(CryptoError::Failure);
                }
                state.begin(PUBLIC, alg, total);
                state.length = state.remaining;
                return Ok(total);
            }
            SignInit if input.len() == CLASSIC_SEED_BYTES => {
                let total = match alg {
                    alg::ED25519 | alg::SM2 => CLASSIC_SIGNATURE_BYTES,
                    _ => {
                        mldsa::parameters(alg)
                            .ok_or(CryptoError::Failure)?
                            .signature_bytes
                    }
                };
                state.abort(data);
                state.begin(SIGNING, alg, total);
                if ck_stream_sign_init(alg, data, input.as_ptr()) != 0 {
                    state.abort(data);
                    return Err(CryptoError::Failure);
                }
            }
            Sm2Identity
                if state.kind == SIGNING
                    && state.alg == alg::SM2
                    && input.len() <= SM2_ID_MAX_BYTES =>
            {
                super::rc_unit(ck_stream_sm2_identity(data, input.as_ptr(), input.len()))?;
            }
            SignUpdate if state.kind == SIGNING => {
                super::rc_unit(ck_stream_sign_update(
                    data,
                    state.alg,
                    input.as_ptr(),
                    input.len(),
                ))?;
            }
            SignFinal if state.kind == SIGNING => {
                state.kind = SIGNATURE;
                let total = usize::from(state.remaining);
                let n = ck_stream_sign_final(data, state.alg, total);
                if n < 0 {
                    state.abort(data);
                    return Err(CryptoError::Failure);
                }
                state.length = n as u16;
                return Ok(total);
            }
            #[cfg(feature = "piv")]
            DecapsulateInit if input.len() == mlkem::SEED_BYTES => {
                let total = mlkem::parameters(alg)
                    .ok_or(CryptoError::Failure)?
                    .ciphertext_bytes;
                state.abort(data);
                ck_stream_decapsulate_init(data, input.as_ptr());
                state.begin(DECAPSULATING, alg, total);
            }
            #[cfg(feature = "piv")]
            DecapsulateUpdate
                if state.kind == DECAPSULATING && input.len() <= usize::from(state.remaining) =>
            {
                ck_stream_decapsulate_update(
                    data,
                    state.position.into(),
                    input.as_ptr(),
                    input.len(),
                );
                state.position += input.len() as u16;
                state.remaining -= input.len() as u16;
            }
            #[cfg(feature = "piv")]
            DecapsulateFinal
                if state.kind == DECAPSULATING
                    && state.remaining == 0
                    && out.len() >= mlkem::SHARED_KEY_BYTES =>
            {
                super::rc_unit(ck_stream_decapsulate_final(
                    data,
                    state.alg,
                    out.as_mut_ptr(),
                ))?;
                return Ok(mlkem::SHARED_KEY_BYTES);
            }
            _ => return Err(CryptoError::Failure),
        }
    }
    Ok(0)
}

#[cfg(feature = "ctap")]
pub(super) fn rewind_public(scratch: &mut CryptoScratch) -> bool {
    let (_, state) = parts(scratch);
    if state.kind != PUBLIC || state.remaining != 0 || mldsa::parameters(state.alg).is_none() {
        return false;
    }
    state.position = 0;
    state.remaining = state.length;
    true
}
