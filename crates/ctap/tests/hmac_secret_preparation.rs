// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    client_pin::{
        Protocol,
        cipher::{self, Direction},
    },
    extensions::hmac_secret::{Input, Prepared},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Length,
    Agree,
    Authenticate,
    Decrypt,
}
#[derive(Default)]
struct Crypto {
    calls: Vec<&'static str>,
    erased: Vec<Vec<u8>>,
    fail: Option<Fault>,
}
impl Crypto {
    fn step(&mut self, name: &'static str, phase: Fault) -> Result<(), Fault> {
        self.calls.push(name);
        if self.fail == Some(phase) {
            Err(phase)
        } else {
            Ok(())
        }
    }
}
impl cipher::Cbc for Crypto {
    type Error = Fault;
    fn aes256_cbc(
        &mut self,
        direction: Direction,
        key: &[u8; 32],
        iv: &[u8; 16],
        bytes: &mut [u8],
    ) -> Result<(), Fault> {
        assert!(matches!(direction, Direction::Decrypt));
        assert_eq!(key, &[0x5a; 32]);
        assert!(iv == &[0x00; 16] || iv == &[0x42; 16]);
        bytes.fill(0x69);
        self.step("cbc", Fault::Decrypt)
    }
}
impl Input for Crypto {
    type Error = Fault;
    const INVALID_LENGTH: Fault = Fault::Length;
    fn decrypt(
        &mut self,
        protocol: Protocol,
        key: &[u8; 32],
        encoded: &mut [u8],
    ) -> Result<(), Fault> {
        cipher::decrypt_in_place(protocol, key, encoded, self)
            .map(|_| ())
            .map_err(|error| match error {
                cipher::Error::InvalidLength => Fault::Length,
                cipher::Error::Primitive(error) => error,
            })
    }
    fn agree(&mut self, _: Protocol, _: &[u8; 64], keys: &mut [u8; 64]) -> Result<(), Fault> {
        keys[..32].fill(0xa5);
        keys[32..].fill(0x5a);
        self.step("agree", Fault::Agree)
    }
    fn authenticate(
        &mut self,
        protocol: Protocol,
        key: &[u8; 32],
        ciphertext: &[u8],
        auth: &[u8],
    ) -> Result<(), Fault> {
        assert_eq!(key, &[0xa5; 32]);
        assert!(ciphertext.iter().all(|&byte| byte == 0x42));
        assert_eq!(auth.len(), protocol.auth_bytes());
        self.step("mac", Fault::Authenticate)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.erased.push(bytes.to_vec());
        bytes.fill(0x00);
    }
}
#[test]
fn both_protocols_commit_only_decrypted_salts_and_aes_key_then_erase_all_capacity() {
    for protocol in [Protocol::One, Protocol::Two] {
        for length in [32, 64] {
            let mut crypto = Crypto::default();
            let mut prepared = Prepared::new();
            let ciphertext = vec![0x42; length + protocol.iv_bytes()];
            prepared
                .prepare(
                    protocol,
                    &[0x00; 64],
                    &ciphertext,
                    &[0x01; 32][..protocol.auth_bytes()],
                    &mut crypto,
                )
                .unwrap();
            assert_eq!(crypto.calls, ["agree", "mac", "cbc"]);
            assert!(prepared.active());
            assert_eq!(crypto.erased.len(), 1);
            assert_eq!(&crypto.erased[0][..32], &[0xa5; 32]);
            assert_eq!(&crypto.erased[0][32..], &[0x5a; 32]);
            let mut captured = Vec::new();
            prepared.clear(|bytes| {
                captured.extend_from_slice(bytes);
                bytes.fill(0x00);
            });
            assert_eq!(&captured[..length], vec![0x69; length]);
            assert_eq!(
                &captured[length..80],
                if protocol == Protocol::Two {
                    [vec![0x42; 16], vec![0x00; 64 - length]].concat()
                } else {
                    vec![0x00; 80 - length]
                }
            );
            assert_eq!(&captured[80..], &[0x5a; 32]);
            assert!(!prepared.active());
            prepared.clear(|bytes| assert!(bytes.iter().all(|&byte| byte == 0x00)));
        }
    }
}
#[test]
fn every_primitive_failure_erases_candidate_and_shared_keys_without_later_calls() {
    for protocol in [Protocol::One, Protocol::Two] {
        for fail in [Fault::Agree, Fault::Authenticate, Fault::Decrypt] {
            let mut prepared = Prepared::new();
            let mut crypto = Crypto {
                fail: Some(fail),
                ..Default::default()
            };
            assert_eq!(
                prepared.prepare(
                    protocol,
                    &[0x00; 64],
                    &vec![0x42; 64 + protocol.iv_bytes()],
                    &[0x01; 32][..protocol.auth_bytes()],
                    &mut crypto
                ),
                Err(fail)
            );
            let expected = match fail {
                Fault::Length => unreachable!(),
                Fault::Agree => &b"agree"[..],
                Fault::Authenticate => &b"agree,mac"[..],
                Fault::Decrypt => &b"agree,mac,cbc"[..],
            };
            assert_eq!(crypto.calls.join(",").as_bytes(), expected);
            assert!(!prepared.active());
            assert!(
                crypto
                    .erased
                    .iter()
                    .any(|bytes| bytes.len() == 64 && bytes[..32] == [0xa5; 32])
            );
            assert!(crypto.erased.iter().any(|bytes| bytes.len() == 112));
            prepared.clear(|bytes| assert!(bytes.iter().all(|&byte| byte == 0x00)));
        }
    }
}

#[test]
fn malformed_lengths_never_reach_agreement_and_erase_previous_preparation() {
    for protocol in [Protocol::One, Protocol::Two] {
        for length in [0, 16, 31, 33, 65, 81] {
            let mut crypto = Crypto::default();
            let mut prepared = Prepared::new();
            prepared
                .prepare(
                    protocol,
                    &[0x00; 64],
                    &vec![0x42; 32 + protocol.iv_bytes()],
                    &[0x01; 32][..protocol.auth_bytes()],
                    &mut crypto,
                )
                .unwrap();
            crypto.calls.clear();
            assert_eq!(
                prepared.prepare(
                    protocol,
                    &[0x00; 64],
                    &vec![0x42; length],
                    &[0x01; 32][..protocol.auth_bytes()],
                    &mut crypto
                ),
                Err(Fault::Length)
            );
            assert!(crypto.calls.is_empty());
            assert!(!prepared.active());
            prepared.clear(|bytes| assert!(bytes.iter().all(|&byte| byte == 0x00)));
        }
    }
}
