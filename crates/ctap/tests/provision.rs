// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    ports::Attestation,
    provision::{self, CertificatePolicy, PRIVATE_KEY_BYTES, ReadError},
};

struct Material {
    key_result: Result<usize, u8>,
    certificate_result: Result<usize, u8>,
    keys: usize,
    lengths: usize,
}
impl Attestation for Material {
    type Error = u8;
    fn key(&mut self, out: &mut [u8; PRIVATE_KEY_BYTES]) -> Result<usize, u8> {
        self.keys += 1;
        // Real sources may have modified output even on an error. Cleanup is
        // the caller's responsibility, not an implicit extra source operation.
        out.fill(0x37);
        self.key_result
    }
    fn certificate_length(&mut self) -> Result<usize, u8> {
        self.lengths += 1;
        self.certificate_result
    }
}

#[test]
fn key_admission_preserves_source_error_and_does_not_read_certificate_or_hide_partial_bytes() {
    for result in [Ok(0), Ok(1), Ok(31), Ok(32), Ok(33), Err(0x42)] {
        let mut material = Material {
            key_result: result,
            certificate_result: Ok(0),
            keys: 0,
            lengths: 0,
        };
        let mut output = [0xa5; PRIVATE_KEY_BYTES + 2];
        assert_eq!(
            provision::key(
                &mut material,
                (&mut output[1..1 + PRIVATE_KEY_BYTES]).try_into().unwrap()
            ),
            match result {
                Ok(PRIVATE_KEY_BYTES) => Ok(()),
                Ok(_) => Err(ReadError::Length),
                Err(error) => Err(ReadError::Source(error)),
            }
        );
        assert_eq!(output[0], 0xa5);
        assert_eq!(output[PRIVATE_KEY_BYTES + 1], 0xa5);
        assert_eq!(
            &output[1..1 + PRIVATE_KEY_BYTES],
            &[0x37; PRIVATE_KEY_BYTES]
        );
        assert_eq!((material.keys, material.lengths), (1, 0));
    }
}

#[test]
fn certificate_profiles_preserve_optional_zero_limits_and_no_key_access() {
    for maximum in [1024, 1152] {
        for optional in [false, true] {
            for result in [
                Ok(0),
                Ok(1),
                Ok(maximum - 1),
                Ok(maximum),
                Ok(maximum + 1),
                Ok(usize::MAX),
                Err(0x42),
            ] {
                let mut material = Material {
                    key_result: Err(0x43),
                    certificate_result: result,
                    keys: 0,
                    lengths: 0,
                };
                let policy = if optional {
                    CertificatePolicy::Optional
                } else {
                    CertificatePolicy::Required
                };
                let expected = match result {
                    Ok(n) if n <= maximum && (optional || n != 0) => Ok(n),
                    Ok(_) => Err(ReadError::Length),
                    Err(error) => Err(ReadError::Source(error)),
                };
                assert_eq!(
                    provision::certificate_length(&mut material, maximum, policy),
                    expected
                );
                assert_eq!((material.keys, material.lengths), (0, 1));
            }
        }
    }
}
