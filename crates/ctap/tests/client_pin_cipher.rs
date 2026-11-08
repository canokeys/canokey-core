// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{Protocol, cipher::*, unpad_pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Random,
    Cipher,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Random,
    Fill,
    Encrypt,
    Decrypt,
}
#[derive(Default)]
struct Backend {
    events: Vec<Event>,
    fail_random: bool,
    fail_cipher: bool,
    iv: Vec<u8>,
}
impl Cbc for Backend {
    type Error = Failure;
    fn aes256_cbc(
        &mut self,
        direction: Direction,
        key: &[u8; 32],
        iv: &[u8; 16],
        bytes: &mut [u8],
    ) -> Result<(), Failure> {
        assert_eq!(key, &[0x71; 32]);
        self.events.push(match direction {
            Direction::Encrypt => Event::Encrypt,
            Direction::Decrypt => Event::Decrypt,
        });
        self.iv = iv.to_vec();
        for byte in bytes {
            *byte ^= 0x5a;
        }
        if self.fail_cipher {
            Err(Failure::Cipher)
        } else {
            Ok(())
        }
    }
}
impl Encryption for Backend {
    fn random_iv(&mut self, iv: &mut [u8; 16]) -> Result<(), Failure> {
        self.events.push(Event::Random);
        iv.fill(0x19);
        if self.fail_random {
            Err(Failure::Random)
        } else {
            Ok(())
        }
    }
}
#[test]
fn borrowed_and_owned_cbc_framing_share_iv_and_preserve_owner_tail() {
    for protocol in [Protocol::One, Protocol::Two] {
        for length in (0..=80).step_by(16) {
            let plain = vec![0x31; length];
            let mut encrypted = vec![0xee; length + 32];
            let mut backend = Backend::default();
            let n = encrypt(protocol, &[0x71; 32], &plain, &mut encrypted, &mut backend).unwrap();
            let prefix = if protocol == Protocol::One { 0 } else { 16 };
            assert_eq!(n, length + prefix);
            assert_eq!(&encrypted[..prefix], &vec![0x19; prefix]);
            assert_eq!(&encrypted[prefix..n], &vec![0x6b; length]);
            assert_eq!(&encrypted[n..], &vec![0xee; encrypted.len() - n]);
            assert_eq!(backend.iv, vec![if prefix == 0 { 0x00 } else { 0x19 }; 16]);
            assert_eq!(
                backend.events,
                if prefix == 0 {
                    vec![Event::Encrypt]
                } else {
                    vec![Event::Random, Event::Encrypt]
                }
            );
            let mut decoded = vec![0xee; length];
            decrypt_to(
                protocol,
                &[0x71; 32],
                &encrypted[..n],
                &mut decoded,
                &mut backend,
            )
            .unwrap();
            assert_eq!(decoded, plain);
            let mut owned = encrypted[..n].to_vec();
            let tail = owned[length..].to_vec();
            assert_eq!(
                decrypt_in_place(protocol, &[0x71; 32], &mut owned, &mut backend),
                Ok(length)
            );
            assert_eq!(&owned[..length], plain);
            assert_eq!(&owned[length..], tail);
        }
    }
}
#[test]
fn malformed_shapes_fail_before_mutation_or_primitive_calls() {
    for protocol in [Protocol::One, Protocol::Two] {
        for length in 0..=97 {
            let valid = length % 16 == 0 && (protocol == Protocol::One || length >= 16);
            if valid {
                continue;
            }
            let mut backend = Backend::default();
            let mut encoded = vec![0xaa; length];
            let mut out = [0xee; 32];
            assert_eq!(
                decrypt_to(protocol, &[0x71; 32], &encoded, &mut out, &mut backend),
                Err(Error::InvalidLength)
            );
            assert_eq!(
                decrypt_in_place(protocol, &[0x71; 32], &mut encoded, &mut backend),
                Err(Error::InvalidLength)
            );
            assert_eq!(encoded, vec![0xaa; length]);
            assert_eq!(out, [0xee; 32]);
            assert!(backend.events.is_empty());
        }
        for (plain, capacity) in [(15, 80), (32, 31), (usize::MAX, 80)] {
            let mut out = vec![0xee; capacity];
            let mut backend = Backend::default();
            assert!(matches!(
                prepare(protocol, plain, &mut out, &mut backend),
                Err(Error::InvalidLength)
            ));
            assert_eq!(out, vec![0xee; capacity]);
            assert!(backend.events.is_empty());
        }
        let mut backend = Backend::default();
        let mut out = [0xee; 31];
        let encoded = [0xaa; 48];
        assert_eq!(
            decrypt_to(protocol, &[0x71; 32], &encoded, &mut out, &mut backend),
            Err(Error::InvalidLength)
        );
        assert_eq!(out, [0xee; 31]);
        assert!(backend.events.is_empty());
    }
}
#[test]
fn rng_and_partial_cipher_failures_preserve_error_and_owner_cleanup_contract() {
    let mut out = [0xee; 48];
    let mut backend = Backend {
        fail_random: true,
        ..Backend::default()
    };
    assert_eq!(
        encrypt(
            Protocol::Two,
            &[0x71; 32],
            &[0x31; 32],
            &mut out,
            &mut backend
        ),
        Err(Error::Primitive(Failure::Random))
    );
    assert_eq!(out, [0xee; 48]);
    assert_eq!(backend.events, [Event::Random]);
    for protocol in [Protocol::One, Protocol::Two] {
        let mut backend = Backend {
            fail_cipher: true,
            ..Backend::default()
        };
        let mut out = [0xee; 48];
        assert_eq!(
            encrypt(protocol, &[0x71; 32], &[0x31; 32], &mut out, &mut backend),
            Err(Error::Primitive(Failure::Cipher))
        );
        let prefix = protocol.iv_bytes();
        assert_eq!(&out[prefix..prefix + 32], &[0x6b; 32]);
        let mut plain = [0xee; 32];
        assert_eq!(
            decrypt_to(
                protocol,
                &[0x71; 32],
                &out[..prefix + 32],
                &mut plain,
                &mut backend
            ),
            Err(Error::Primitive(Failure::Cipher))
        );
        assert_eq!(plain, [0x31; 32]);
        // The mechanism reports failure without publishing or silently erasing
        // a product-owned buffer. Product error-path tests verify final erasure.
        assert_eq!(backend.events.last(), Some(&Event::Decrypt));
    }
}
#[test]
fn prepared_output_keeps_rng_before_plaintext_production_and_encryption() {
    let mut out = [0xee; 80];
    let mut backend = Backend::default();
    let mut prepared = prepare(Protocol::Two, 64, &mut out, &mut backend).unwrap();
    backend.events.push(Event::Fill);
    prepared.body_mut().fill(0x31);
    assert_eq!(prepared.finish(&[0x71; 32], &mut backend), Ok(80));
    assert_eq!(backend.events, [Event::Random, Event::Fill, Event::Encrypt]);
}
#[test]
fn only_trailing_pin_padding_is_removed() {
    for length in 0..=64 {
        let mut padded = [0x00; 64];
        padded[..length].fill(0x61);
        assert_eq!(unpad_pin(&padded), &[0x61; 64][..length]);
    }
    let mut padded = [0x00; 64];
    padded[..5].copy_from_slice(b"ab\0cd");
    assert_eq!(unpad_pin(&padded), b"ab\0cd");
    assert_eq!(
        canokey_ctap::client_pin::validate_pin(unpad_pin(&padded), 4),
        None
    );
}
