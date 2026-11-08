// SPDX-License-Identifier: Apache-2.0
//! PIN/UV authenticator verification using the owner's existing digest scratch.
use super::KEY_BYTES;

/// Compute, compare the selected SHA-256 prefix, erase the complete primitive
/// output, then propagate primitive failure. Products admit protocol/length and
/// provide their constant-time comparison. Invalid public lengths still compute
/// and erase, preserving adapters that authenticate before rejecting scope.
/// No digest copy or primitive scratch is allocated here; all calls are synchronous.
#[inline]
pub fn verify<E>(
    auth: &[u8],
    auth_bytes: usize,
    scratch: &mut [u8],
    compute: impl FnOnce(&mut [u8]) -> Result<(), E>,
    equal: impl FnOnce(&[u8], &[u8]) -> bool,
    wipe: impl FnOnce(&mut [u8]),
) -> Result<bool, E> {
    let result = compute(scratch);
    let valid = scratch
        .get(..KEY_BYTES)
        .and_then(|digest| digest.get(..auth_bytes))
        .is_some_and(|prefix| equal(auth, prefix));
    wipe(scratch);
    result?;
    Ok(valid)
}
