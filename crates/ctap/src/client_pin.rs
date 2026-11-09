// SPDX-License-Identifier: Apache-2.0
//! PIN/UV protocol key derivation and PIN text rules, without session policy.

pub mod agreement;
pub mod authentication;
pub mod cipher;
pub mod request;
pub mod response;
pub mod retry;
pub mod token;

pub const KEY_BYTES: usize = 32;
pub const MAX_PIN_BYTES: usize = 63;
const HKDF_SALT: [u8; KEY_BYTES] = [0x00; KEY_BYTES];
// CTAP 2.1 PIN/UV protocol 2: HKDF-Expand info followed by block counter 0x01.
const HMAC_INFO_BLOCK: &[u8] = b"CTAP2 HMAC key\x01";
const AES_INFO_BLOCK: &[u8] = b"CTAP2 AES key\x01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    One = 0x01,
    Two = 0x02,
}
impl Protocol {
    pub fn decode(value: u64) -> Option<Self> {
        match value {
            0x01 => Some(Self::One),
            0x02 => Some(Self::Two),
            _ => None,
        }
    }
    pub const fn auth_bytes(self) -> usize {
        match self {
            Self::One => 16,
            Self::Two => 32,
        }
    }
    pub const fn iv_bytes(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 16,
        }
    }
}

/// Synchronous primitive calls borrow existing product scratch. Implementations
/// must not retain inputs and must erase their own primitive scratch on failure.
pub trait Derivation {
    type Error;
    fn sha256(&mut self, input: &[u8], out: &mut [u8; KEY_BYTES]) -> Result<(), Self::Error>;
    fn hmac_sha256(
        &mut self,
        key: &[u8; KEY_BYTES],
        input: &[u8],
        out: &mut [u8; KEY_BYTES],
    ) -> Result<(), Self::Error>;
    fn wipe(&mut self, bytes: &mut [u8]);
}

/// Input is the validated P-256 ECDH x coordinate. Callers own its erasure and
/// the lifetime of both output keys. No token or authorization is created here.
/// The temporary extraction key is erased before returning on every path.
pub fn derive<D: Derivation>(
    protocol: Protocol,
    agreement: &[u8; KEY_BYTES],
    mac_key: &mut [u8; KEY_BYTES],
    aes_key: &mut [u8; KEY_BYTES],
    backend: &mut D,
) -> Result<(), D::Error> {
    if protocol == Protocol::One {
        backend.sha256(agreement, mac_key)?;
        aes_key.copy_from_slice(mac_key);
        return Ok(());
    }
    let mut extraction_key = [0x00; KEY_BYTES];
    let result = (|| {
        backend.hmac_sha256(&HKDF_SALT, agreement, &mut extraction_key)?;
        backend.hmac_sha256(&extraction_key, HMAC_INFO_BLOCK, mac_key)?;
        backend.hmac_sha256(&extraction_key, AES_INFO_BLOCK, aes_key)
    })();
    backend.wipe(&mut extraction_key);
    result
}

/// Unpadded PINs contain valid UTF-8, no NUL, and at most 63 bytes. The product
/// supplies its authenticated minimum in Unicode scalar values, not bytes.
/// Padding removal belongs to the encrypted-field adapter.
pub fn validate_pin(bytes: &[u8], minimum: usize) -> Option<&str> {
    if bytes.is_empty() || bytes.len() > MAX_PIN_BYTES || bytes.contains(&0x00) {
        return None;
    }
    let text = core::str::from_utf8(bytes).ok()?;
    if text.chars().count() < minimum {
        return None;
    }
    Some(text)
}

/// CTAP newPinEnc is 64 bytes with trailing zero padding. Only this encrypted
/// field removes padding; validate_pin still rejects NUL inside the PIN.
pub fn unpad_pin(padded: &[u8; request::PADDED_PIN_BYTES]) -> &[u8] {
    let length = padded
        .iter()
        .rposition(|byte| *byte != 0x00)
        .map_or(0, |index| index + 1);
    &padded[..length]
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend {
        calls: usize,
        fail_at: usize,
        wipes: usize,
    }
    impl Derivation for Backend {
        type Error = ();
        fn sha256(&mut self, input: &[u8], out: &mut [u8; KEY_BYTES]) -> Result<(), ()> {
            assert_eq!(input, &[0x42; KEY_BYTES]);
            self.calls += 1;
            out.fill(0x51);
            Ok(())
        }
        fn hmac_sha256(
            &mut self,
            key: &[u8; KEY_BYTES],
            input: &[u8],
            out: &mut [u8; KEY_BYTES],
        ) -> Result<(), ()> {
            self.calls += 1;
            match self.calls {
                1 => {
                    assert_eq!(key, &HKDF_SALT);
                    assert_eq!(input, &[0x42; KEY_BYTES]);
                }
                2 => {
                    assert_eq!(key, &[0x01; KEY_BYTES]);
                    assert_eq!(input, HMAC_INFO_BLOCK);
                }
                3 => {
                    assert_eq!(key, &[0x01; KEY_BYTES]);
                    assert_eq!(input, AES_INFO_BLOCK);
                }
                _ => panic!("unexpected primitive call"),
            }
            // Simulate a primitive that writes before reporting failure.
            out.fill(self.calls as u8);
            if self.calls == self.fail_at {
                Err(())
            } else {
                Ok(())
            }
        }
        fn wipe(&mut self, bytes: &mut [u8]) {
            assert_eq!(bytes, &[0x01; KEY_BYTES]);
            bytes.fill(0x00);
            self.wipes += 1;
        }
    }
    #[test]
    fn derivation_order_and_extract_erasure_on_every_primitive_failure() {
        for fail_at in 0..=3 {
            let mut backend = Backend {
                calls: 0,
                fail_at,
                wipes: 0,
            };
            let mut mac_key = [0x00; KEY_BYTES];
            let mut aes_key = [0x00; KEY_BYTES];
            let result = derive(
                Protocol::Two,
                &[0x42; KEY_BYTES],
                &mut mac_key,
                &mut aes_key,
                &mut backend,
            );
            assert_eq!(result.is_ok(), fail_at == 0);
            assert_eq!(backend.calls, if fail_at == 0 { 3 } else { fail_at });
            assert_eq!(backend.wipes, 1);
            if result.is_ok() {
                assert_eq!(mac_key, [0x02; KEY_BYTES]);
                assert_eq!(aes_key, [0x03; KEY_BYTES]);
            }
        }
    }
    #[test]
    fn protocol_one_hashes_once_and_reuses_the_key() {
        let mut backend = Backend {
            calls: 0,
            fail_at: 0,
            wipes: 0,
        };
        let mut mac_key = [0x00; KEY_BYTES];
        let mut aes_key = [0x00; KEY_BYTES];
        derive(
            Protocol::One,
            &[0x42; KEY_BYTES],
            &mut mac_key,
            &mut aes_key,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(backend.wipes, 0);
        assert_eq!(mac_key, [0x51; KEY_BYTES]);
        assert_eq!(aes_key, mac_key);
    }
    #[test]
    fn pin_limits_count_unicode_scalars_and_reject_embedded_padding() {
        assert_eq!(validate_pin("密码🔑a".as_bytes(), 4), Some("密码🔑a"));
        assert_eq!(validate_pin("密码🔑".as_bytes(), 4), None);
        for invalid in [&b""[..], &b"ab\0cd"[..], &[0xff][..], &[0x61; 64][..]] {
            assert_eq!(validate_pin(invalid, 0), None);
        }
        assert!(validate_pin(&[0x61; MAX_PIN_BYTES], MAX_PIN_BYTES).is_some());
        // A trailing NUL is padding only in the encrypted-field adapter.
        assert_eq!(validate_pin(b"abcd\0", 4), None);
    }
    #[test]
    fn protocol_numbers_and_wire_lengths_are_exact() {
        for value in [0x00, 0x03, 0x100, u64::MAX] {
            assert_eq!(Protocol::decode(value), None);
        }
        for (value, auth, iv) in [(0x01, 16, 0), (0x02, 32, 16)] {
            let protocol = Protocol::decode(value).unwrap();
            assert_eq!(protocol.auth_bytes(), auth);
            assert_eq!(protocol.iv_bytes(), iv);
        }
    }
}
