// SPDX-License-Identifier: Apache-2.0
#[cfg(any(feature = "admin", feature = "openpgp", feature = "piv", test))]
pub(crate) mod pin;

#[cfg(any(feature = "openpgp", feature = "piv"))]
pub(crate) mod key_storage;

/// Compare every overlapping byte and the public length difference. Keep one
/// implementation for applet authentication and PIN checks.
#[inline(never)]
pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    a.iter()
        .zip(b)
        .fold(a.len() ^ b.len(), |diff, (a, b)| diff | usize::from(a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::equal;

    #[test]
    fn equality_checks_all_positions_and_full_lengths() {
        assert!(equal(&[], &[]));
        let bytes = [0xa5; 64];
        assert!(equal(&bytes, &bytes));
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(!equal(&bytes, &changed));
            assert!(!equal(&changed, &bytes));
        }
        for length in [0, 1, 63, 64, 255, 256, 257] {
            let zeros = [0; 257];
            assert_eq!(equal(&zeros[..length], &zeros[..64]), length == 64);
            assert_eq!(equal(&zeros[..64], &zeros[..length]), length == 64);
            assert_eq!(equal(&zeros[..length], &[]), length == 0);
            assert_eq!(equal(&[], &zeros[..length]), length == 0);
        }
    }
}
