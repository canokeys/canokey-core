// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::ports::*;
use std::{cell::RefCell, vec::Vec};

const ROOT: [u8; shared::KEY_BYTES] = [0x69; shared::KEY_BYTES];
const RP: [u8; shared::RP_HASH_BYTES] = [0x31; shared::RP_HASH_BYTES];
const TAG: u8 = 0x7a;
const SEED: u8 = 0x22;
const KEY_SENTINEL: u8 = 0xcc;

#[derive(Default)]
struct Backend {
    expected_prefix: Vec<u8>,
    expected_settings: Vec<u8>,
    domains: Vec<u8>,
    seed: Option<[u8; shared::KEY_BYTES]>,
    fail_domain: Option<u8>,
    load_error: Option<StorageError>,
    wiped: RefCell<Vec<Vec<u8>>>,
}
impl Storage for Backend {
    fn load(&mut self, record: Record, output: &mut [u8]) -> Result<usize, StorageError> {
        assert_eq!(record, Record::CtapMaster);
        output.copy_from_slice(&ROOT);
        self.load_error.map_or(Ok(ROOT.len()), Err)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        panic!("opening cannot write storage")
    }
}
impl Crypto for Backend {
    fn mac(
        &mut self,
        algorithm: u8,
        root: &[u8],
        input: &[u8],
        output: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        // Native MAC ABI selector 0x02 is HMAC-SHA-256. Transcript order is
        // domain || 18-byte handle prefix || RP hash || optional SM2 settings.
        assert_eq!(algorithm, 0x02);
        assert_eq!(root, ROOT);
        assert_eq!(&input[1..1 + shared::TAG_OFFSET], self.expected_prefix);
        let rp_offset = 1 + shared::TAG_OFFSET;
        assert_eq!(&input[rp_offset..rp_offset + RP.len()], RP);
        assert_eq!(&input[rp_offset + RP.len()..], self.expected_settings);
        self.domains.push(input[0]);
        output.fill(0xd7);
        if self.fail_domain == Some(input[0]) {
            return Err(CryptoError::Failure);
        }
        match input[0] {
            0x00 => output[..shared::KEY_BYTES].fill(TAG),
            0x01 => output[..shared::KEY_BYTES]
                .copy_from_slice(&self.seed.unwrap_or([SEED; shared::KEY_BYTES])),
            _ => panic!("unexpected credential domain"),
        }
        Ok(())
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        panic!("opening cannot redraw a nonce")
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
impl Device for Backend {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        unreachable!()
    }
    fn touched(&mut self) -> bool {
        unreachable!()
    }
    fn progress(&mut self) -> bool {
        unreachable!()
    }
    fn led(&mut self, _: bool) {
        unreachable!()
    }
}
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        self.wiped.borrow_mut().push(bytes.to_vec());
        bytes.fill(0x00);
    }
}
fn handle(scheme: Scheme) -> Id {
    let mut id = [0x11; shared::ID_BYTES];
    id[shared::ALGORITHM_OFFSET] = scheme as u8;
    id[shared::POLICY_OFFSET] = 0x07;
    id[shared::TAG_OFFSET..].fill(TAG);
    id
}
fn run(
    id: &Id,
    crypto: &mut Backend,
    storage: &mut Backend,
    memory: &Backend,
    key: &mut KeyMaterial,
) -> Result<u8, Status> {
    let mut device = Backend::default();
    open(
        id,
        super::super::settings::Sm2::DEFAULT,
        &RP,
        key,
        &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage,
            crypto,
            device: &mut device,
            memory,
        },
    )
}
fn mac_backend(id: &Id) -> Backend {
    Backend {
        expected_prefix: id[..shared::TAG_OFFSET].to_vec(),
        expected_settings: if id[shared::ALGORITHM_OFFSET] == Scheme::Sm2 as u8 {
            super::super::settings::Sm2::DEFAULT.encode().to_vec()
        } else {
            Vec::new()
        },
        ..Backend::default()
    }
}

#[test]
fn actual_open_authenticates_before_seed_for_every_admitted_scheme_and_primitive_failure() {
    for scheme in [
        Scheme::P256,
        Scheme::Ed25519,
        Scheme::Sm2,
        Scheme::MlDsa65,
        Scheme::MlDsa44,
    ] {
        for valid_tag in [false, true] {
            for failure in [None, Some(0x00), Some(0x01)] {
                let mut id = handle(scheme);
                if !valid_tag {
                    id[shared::TAG_OFFSET] ^= 0x01;
                }
                let mut crypto = mac_backend(&id);
                crypto.fail_domain = failure;
                let memory = Backend::default();
                let mut key = KeyMaterial::new();
                key.bytes.fill(KEY_SENTINEL);
                let actual = run(&id, &mut crypto, &mut Backend::default(), &memory, &mut key);
                let expected = if failure == Some(0x00) {
                    Err(Status::Other)
                } else if !valid_tag {
                    Err(Status::NoCredentials)
                } else if failure == Some(0x01) {
                    Err(Status::Other)
                } else {
                    Ok(native_algorithm(scheme))
                };
                assert_eq!(actual, expected);
                assert_eq!(
                    crypto.domains,
                    if valid_tag && failure != Some(0x00) {
                        std::vec![0x00, 0x01]
                    } else {
                        std::vec![0x00]
                    }
                );
                let wiped = memory.wiped.borrow();
                assert!(wiped.iter().any(|bytes| bytes == &ROOT));
                assert_eq!(
                    wiped.iter().filter(|bytes| bytes.len() == 64).count(),
                    crypto.domains.len()
                );
                if expected.is_err() {
                    assert!(key.bytes.iter().all(|byte| *byte == 0x00));
                    assert!(wiped.iter().any(|bytes| bytes.len() == key.bytes.len()));
                } else {
                    assert_eq!(&key.bytes[..shared::KEY_BYTES], &[SEED; shared::KEY_BYTES]);
                    assert!(
                        key.bytes[shared::KEY_BYTES..]
                            .iter()
                            .all(|byte| *byte == KEY_SENTINEL)
                    );
                }
            }
        }
    }
}

#[test]
fn authenticated_invalid_scalar_is_rejected_without_nonce_retry_and_non_scalar_seeds_are_admitted()
{
    for scheme in [
        Scheme::P256,
        Scheme::Ed25519,
        Scheme::Sm2,
        Scheme::MlDsa65,
        Scheme::MlDsa44,
    ] {
        for seed in [[0x00; shared::KEY_BYTES], [0xff; shared::KEY_BYTES]] {
            let id = handle(scheme);
            let mut crypto = mac_backend(&id);
            crypto.seed = Some(seed);
            let memory = Backend::default();
            let mut key = KeyMaterial::new();
            key.bytes.fill(KEY_SENTINEL);
            let result = run(&id, &mut crypto, &mut Backend::default(), &memory, &mut key);
            let scalar = matches!(scheme, Scheme::P256 | Scheme::Sm2);
            assert_eq!(
                result,
                if scalar {
                    Err(Status::NoCredentials)
                } else {
                    Ok(native_algorithm(scheme))
                }
            );
            assert_eq!(crypto.domains, [0x00, 0x01]);
            if scalar {
                assert!(key.bytes.iter().all(|byte| *byte == 0x00));
            } else {
                assert_eq!(&key.bytes[..shared::KEY_BYTES], &seed);
            }
            assert!(memory.wiped.borrow().iter().any(|bytes| bytes == &ROOT));
        }
    }
}

#[test]
fn root_read_failure_and_unknown_scheme_erase_key_without_any_mac() {
    for error in [
        StorageError::Missing,
        StorageError::Unavailable,
        StorageError::Uncertain,
    ] {
        let id = handle(Scheme::P256);
        let mut storage = Backend {
            load_error: Some(error),
            ..Backend::default()
        };
        let mut crypto = mac_backend(&id);
        let memory = Backend::default();
        let mut key = KeyMaterial::new();
        key.bytes.fill(KEY_SENTINEL);
        assert_eq!(
            run(&id, &mut crypto, &mut storage, &memory, &mut key),
            Err(if error == StorageError::Missing {
                Status::NoCredentials
            } else {
                Status::Other
            })
        );
        assert!(crypto.domains.is_empty());
        assert!(key.bytes.iter().all(|byte| *byte == 0x00));
        assert!(memory.wiped.borrow().iter().any(|bytes| bytes == &ROOT));
    }
    let mut id = handle(Scheme::P256);
    id[shared::ALGORITHM_OFFSET] = 0xff;
    let mut crypto = Backend::default();
    let memory = Backend::default();
    let mut key = KeyMaterial::new();
    key.bytes.fill(KEY_SENTINEL);
    assert_eq!(
        run(&id, &mut crypto, &mut Backend::default(), &memory, &mut key),
        Err(Status::NoCredentials)
    );
    assert!(crypto.domains.is_empty());
    assert!(key.bytes.iter().all(|byte| *byte == 0x00));
}
