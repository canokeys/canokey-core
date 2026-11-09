// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    client_pin::{
        Protocol,
        cipher::{Cbc, Direction, Encryption, Error},
    },
    extensions::hmac_secret::{self, MAX_OUTPUT_BYTES, MAX_SALT_BYTES, Output, SALT_BYTES},
};
const KEY: [u8; SALT_BYTES] = [0x71; SALT_BYTES];
const AES_KEY: [u8; SALT_BYTES] = [0x42; SALT_BYTES];
const IV_BYTES: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Random,
    Mac(usize),
    Cipher,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Random,
    Mac(usize),
    Encrypt,
}
#[derive(Default)]
struct Backend {
    events: Vec<Event>,
    fail: Option<Failure>,
    macs: usize,
    targets: Vec<usize>,
}
impl Cbc for Backend {
    type Error = Failure;
    fn aes256_cbc(
        &mut self,
        direction: Direction,
        key: &[u8; SALT_BYTES],
        iv: &[u8; IV_BYTES],
        body: &mut [u8],
    ) -> Result<(), Failure> {
        assert!(matches!(direction, Direction::Encrypt));
        assert_eq!(key, &AES_KEY);
        self.events.push(Event::Encrypt);
        assert!(iv.iter().all(|&b| b == 0x00) || iv.iter().all(|&b| b == 0x19));
        for byte in body {
            *byte ^= 0x5a;
        }
        if self.fail == Some(Failure::Cipher) {
            Err(Failure::Cipher)
        } else {
            Ok(())
        }
    }
}
impl Encryption for Backend {
    fn random_iv(&mut self, iv: &mut [u8; IV_BYTES]) -> Result<(), Failure> {
        self.events.push(Event::Random);
        iv.fill(0x19);
        if self.fail == Some(Failure::Random) {
            Err(Failure::Random)
        } else {
            Ok(())
        }
    }
}
impl Output for Backend {
    fn mac(
        &mut self,
        key: &[u8; SALT_BYTES],
        salt: &[u8; SALT_BYTES],
        out: &mut [u8; SALT_BYTES],
    ) -> Result<(), Failure> {
        assert_eq!(key, &KEY);
        self.macs += 1;
        self.events.push(Event::Mac(self.macs));
        self.targets.push(out.as_ptr() as usize);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = salt[i] ^ key[i] ^ 0x39;
        }
        if self.fail == Some(Failure::Mac(self.macs)) {
            Err(Failure::Mac(self.macs))
        } else {
            Ok(())
        }
    }
}
#[test]
fn both_protocols_fill_the_ciphertext_body_directly_at_every_output_capacity() {
    let salts: Vec<_> = (0..MAX_SALT_BYTES).map(|i| i as u8).collect();
    for protocol in [Protocol::One, Protocol::Two] {
        for length in [SALT_BYTES, MAX_SALT_BYTES] {
            let count = length + protocol.iv_bytes();
            for capacity in 0..=count + 1 {
                let mut backing = [0xa5; MAX_OUTPUT_BYTES + 3];
                let address = backing.as_ptr() as usize + 1;
                let mut backend = Backend::default();
                let result = hmac_secret::output(
                    protocol,
                    &AES_KEY,
                    &KEY,
                    &salts[..length],
                    &mut backing[1..1 + capacity],
                    &mut backend,
                );
                assert_eq!(backing[0], 0xa5);
                assert!(backing[1 + capacity..].iter().all(|&b| b == 0xa5));
                if capacity < count {
                    assert_eq!(result, Err(Error::InvalidLength));
                    assert!(backend.events.is_empty());
                    assert!(backing.iter().all(|&b| b == 0xa5));
                    continue;
                }
                assert_eq!(result, Ok(count));
                let mut events = Vec::new();
                if protocol == Protocol::Two {
                    events.push(Event::Random);
                }
                events.extend((1..=length / SALT_BYTES).map(Event::Mac));
                events.push(Event::Encrypt);
                assert_eq!(backend.events, events);
                let mut expected = vec![0x19; protocol.iv_bytes()];
                expected.extend(salts[..length].iter().map(|salt| salt ^ 0x71 ^ 0x39 ^ 0x5a));
                assert_eq!(&backing[1..1 + count], expected);
                assert!(backing[1 + count..].iter().all(|&b| b == 0xa5));
                assert_eq!(
                    backend.targets,
                    (0..length / SALT_BYTES)
                        .map(|i| address + protocol.iv_bytes() + i * SALT_BYTES)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
#[test]
fn primitive_failures_stop_before_later_macs_or_aes_and_preserve_error_identity() {
    for protocol in [Protocol::One, Protocol::Two] {
        for failure in [
            Failure::Random,
            Failure::Mac(1),
            Failure::Mac(2),
            Failure::Cipher,
        ] {
            if protocol == Protocol::One && failure == Failure::Random {
                continue;
            }
            let mut output = [0xa5; MAX_OUTPUT_BYTES];
            let mut backend = Backend {
                fail: Some(failure),
                ..Default::default()
            };
            assert_eq!(
                hmac_secret::output(
                    protocol,
                    &AES_KEY,
                    &KEY,
                    &[0x21; MAX_SALT_BYTES],
                    &mut output,
                    &mut backend
                ),
                Err(Error::Primitive(failure))
            );
            let mut expected = Vec::new();
            if protocol == Protocol::Two {
                expected.push(Event::Random);
            }
            if failure != Failure::Random {
                expected.push(Event::Mac(1));
                if failure != Failure::Mac(1) {
                    expected.push(Event::Mac(2));
                }
                if failure == Failure::Cipher {
                    expected.push(Event::Encrypt);
                }
            }
            assert_eq!(backend.events, expected);
            if failure == Failure::Random {
                assert_eq!(output, [0xa5; MAX_OUTPUT_BYTES]);
            } else {
                assert_ne!(output, [0xa5; MAX_OUTPUT_BYTES]);
            }
        }
    }
}
#[test]
fn malformed_salt_shapes_never_touch_output_or_invoke_primitives() {
    for protocol in [Protocol::One, Protocol::Two] {
        for length in 0..=MAX_OUTPUT_BYTES {
            if matches!(length, SALT_BYTES | MAX_SALT_BYTES) {
                continue;
            }
            let mut backend = Backend::default();
            let mut output = [0xa5; MAX_OUTPUT_BYTES];
            assert_eq!(
                hmac_secret::output(
                    protocol,
                    &AES_KEY,
                    &KEY,
                    &[0x00; MAX_OUTPUT_BYTES][..length],
                    &mut output,
                    &mut backend
                ),
                Err(Error::InvalidLength)
            );
            assert_eq!(output, [0xa5; MAX_OUTPUT_BYTES]);
            assert!(backend.events.is_empty());
        }
    }
}
