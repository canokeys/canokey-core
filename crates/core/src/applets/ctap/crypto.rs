// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP authentication primitives. Call only after request PKE release.
use super::Status;
use crate::ports::Platform;

pub(super) use crate::mechanisms::equal;
pub(super) fn mac(
    key: &[u8],
    input: &[u8],
    out: &mut [u8; 32],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    let mut full = [0; 64];
    let result = p
        .crypto
        .mac(2, key, input, &mut full)
        .map_err(|_| Status::Other);
    if result.is_ok() {
        out.copy_from_slice(&full[..32]);
    }
    p.memory.wipe(&mut full);
    result
}
