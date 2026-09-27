// SPDX-License-Identifier: Apache-2.0
//! ECDSA/SM2 signature wire encoding, shared by card and FIDO applets.
use crate::response::StatusWord as Sw;
const P521_COORDINATE_BYTES: usize = 66;
const MAX_RAW_SIGNATURE_BYTES: usize = 2 * P521_COORDINATE_BYTES;
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
    // Reserve the maximum DER overhead before encoding forwards. Even with
    // both sign pads, each write ends before the next unread coordinate.
    out.copy_within(..n, DER_MAX_HEADER_BYTES);
    let mut at = 3;
    for coordinate in 0..2 {
        let start = DER_MAX_HEADER_BYTES + coordinate * width;
        let skip = out[start..start + width]
            .iter()
            .position(|v| *v != 0)
            .unwrap_or(width - 1);
        let start = start + skip;
        let len = width - skip;
        let pad = usize::from(out[start] & 0x80 != 0);
        out[at] = 2;
        out[at + 1] = (len + pad) as u8;
        at += 2;
        out[at..at + pad].fill(0);
        at += pad;
        out.copy_within(start..start + len, at);
        at += len;
    }
    let body = at - 3;
    let start = if body < 128 {
        out[1] = 0x30;
        out[2] = body as u8;
        1
    } else {
        out[0] = 0x30;
        out[1] = 0x81;
        out[2] = body as u8;
        0
    };
    out.copy_within(start..at, 0);
    Ok(at - start)
}
