// SPDX-License-Identifier: Apache-2.0
//! ECDSA/SM2 signature wire encoding, shared by card and FIDO applets.
use crate::response::StatusWord as Sw;
const P521_COORDINATE_BYTES: usize = 66;
const MAX_RAW_SIGNATURE_BYTES: usize = 2 * P521_COORDINATE_BYTES;
const DER_BUFFER_BYTES: usize = MAX_RAW_SIGNATURE_BYTES + 12;
const DER_MAX_HEADER_BYTES: usize = 9;

pub fn der_signature(out: &mut [u8], n: usize) -> Result<usize, Sw> {
    if n == 0
        || !n.is_multiple_of(2)
        || n > MAX_RAW_SIGNATURE_BYTES
        || out.len() < n + DER_MAX_HEADER_BYTES
    {
        return Err(Sw::UNABLE_TO_PROCESS);
    }
    let width = n / 2;
    let mut der = [0; DER_BUFFER_BYTES];
    let mut at = 3;
    for value in out[..n].chunks_exact(width) {
        let skip = value
            .iter()
            .position(|v| *v != 0)
            .unwrap_or(value.len() - 1);
        let v = &value[skip..];
        let pad = usize::from(v[0] & 0x80 != 0);
        der[at] = 2;
        der[at + 1] = (v.len() + pad) as u8;
        at += 2;
        der[at..at + pad].fill(0);
        at += pad;
        der[at..at + v.len()].copy_from_slice(v);
        at += v.len();
    }
    let body = at - 3;
    let start = if body < 128 {
        der[1] = 0x30;
        der[2] = body as u8;
        1
    } else {
        der[0] = 0x30;
        der[1] = 0x81;
        der[2] = body as u8;
        0
    };
    out[..at - start].copy_from_slice(&der[start..at]);
    Ok(at - start)
}
