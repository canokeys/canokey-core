// SPDX-License-Identifier: Apache-2.0
//! WebAuthn authenticatorData offsets and fixed headers, in network byte order.

pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const AT: u8 = 0x40;
pub const ED: u8 = 0x80;
pub const FLAGS_OFFSET: usize = 32;
pub const COUNTER_OFFSET: usize = FLAGS_OFFSET + 1;
pub const HEADER_BYTES: usize = COUNTER_OFFSET + 4;
pub const CREDENTIAL_LENGTH_OFFSET: usize = HEADER_BYTES + 16; // AAGUID16.
pub const CREDENTIAL_OFFSET: usize = CREDENTIAL_LENGTH_OFFSET + 2;

/// rpIdHash(32), flags(1), signature counter(4), as WebAuthn section 6.1.
/// The caller reads the counter and owns extension flags and output publication.
#[inline(always)]
pub fn header(output: &mut [u8], rp: &[u8; 32], counter: &[u8; 4], up: bool, uv: bool, make: bool) {
    output[..FLAGS_OFFSET].copy_from_slice(rp);
    output[FLAGS_OFFSET] =
        if up { UP } else { 0x00 } | if uv { UV } else { 0x00 } | if make { AT } else { 0x00 };
    output[COUNTER_OFFSET..HEADER_BYTES].copy_from_slice(counter);
}
/// Attested credential data: AAGUID(16), ID length(u16 bytes), ID.
/// Products admit the credential ID and lend a sufficiently sized authData view.
#[inline(always)]
pub fn attested(output: &mut [u8], aaguid: &[u8; 16], id: &[u8]) {
    output[HEADER_BYTES..CREDENTIAL_LENGTH_OFFSET].copy_from_slice(aaguid);
    output[CREDENTIAL_LENGTH_OFFSET..CREDENTIAL_OFFSET]
        .copy_from_slice(&(id.len() as u16).to_be_bytes());
    output[CREDENTIAL_OFFSET..CREDENTIAL_OFFSET + id.len()].copy_from_slice(id);
}
