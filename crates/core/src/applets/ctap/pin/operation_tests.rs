// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::{ports::*, runtime::workspace::SessionWorkspace};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, vec, vec::Vec};

#[derive(Default)]
struct Backend {
    now: u32,
    mac_calls: usize,
    generated: usize,
    exported: usize,
    agreed: usize,
    expected_peer: Option<[u8; 64]>,
    reads: usize,
    fail_generate: bool,
    fail_export: bool,
    fail_agree: bool,
    agreed_bytes: Option<usize>,
    sha_calls: usize,
    fail_sha_at: usize,
    fail_mac: bool,
    fail_read: bool,
    fail_patch: bool,
    fail_patch_at: usize,
    fail_patch_durable: bool,
    fail_decrypt: bool,
    fail_decrypt_at: usize,
    new_pin: Option<&'static [u8]>,
    fail_replace: bool,
    fail_replace_durable: bool,
    replacements: Vec<Vec<u8>>,
    fail_encrypt: bool,
    fail_random_at: usize,
    random_calls: usize,
    decrypt_calls: usize,
    encrypt_calls: usize,
    retries_written: Vec<u8>,
    record: Option<Vec<u8>>,
    wiped: RefCell<Vec<Vec<u8>>>,
}
impl Storage for Backend {
    fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        self.reads += 1;
        assert_eq!(id, Record::CtapPin);
        let Some(record) = &self.record else {
            return Err(StorageError::Missing);
        };
        out[..record.len()].copy_from_slice(record);
        if self.fail_read {
            Err(StorageError::Unavailable)
        } else {
            Ok(record.len())
        }
    }
    fn replace_at(&mut self, id: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        assert_eq!(id, Record::CtapPin);
        assert_eq!(offset, RETRIES as u32);
        assert_eq!(input.len(), 1);
        self.retries_written.push(input[0]);
        if self.fail_patch || self.retries_written.len() == self.fail_patch_at {
            if self.fail_patch_durable {
                self.record.as_mut().unwrap()[RETRIES] = input[0];
            }
            return Err(StorageError::Unavailable);
        }
        self.record.as_mut().unwrap()[RETRIES] = input[0];
        Ok(())
    }
    fn replace(&mut self, id: Record, input: &[u8]) -> Result<(), StorageError> {
        assert_eq!(id, Record::CtapPin);
        self.replacements.push(input.to_vec());
        if !self.fail_replace || self.fail_replace_durable {
            self.record = Some(input.to_vec());
        }
        if self.fail_replace {
            Err(StorageError::Unavailable)
        } else {
            Ok(())
        }
    }
}
impl Crypto for Backend {
    fn key_operation(
        &mut self,
        op: KeyOperation,
        algorithm: u8,
        key: &mut KeyMaterial,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert_eq!(algorithm, alg::P256);
        match op {
            KeyOperation::Generate => {
                self.generated += 1;
                key.bytes.fill(7);
                if self.fail_generate {
                    Err(CryptoError::Failure)
                } else {
                    Ok(0)
                }
            }
            KeyOperation::Public => {
                self.exported += 1;
                assert_eq!(&key.bytes[..32], &[7; 32]);
                out[..32].fill(8);
                out[32..64].fill(9);
                if self.fail_export {
                    Err(CryptoError::Failure)
                } else {
                    Ok(64)
                }
            }
            KeyOperation::Agree => {
                self.agreed += 1;
                assert_eq!(&key.bytes[..32], &[7; 32]);
                assert_eq!(input, self.expected_peer.unwrap_or([0x05; 64]));
                out[..32].fill(0x17);
                if self.fail_agree {
                    Err(CryptoError::Failure)
                } else {
                    Ok(self.agreed_bytes.unwrap_or(32))
                }
            }
            _ => unreachable!(),
        }
    }
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        self.sha_calls += 1;
        out.copy_from_slice(&Sha256::digest(input));
        if self.sha_calls == self.fail_sha_at {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn mac(
        &mut self,
        algorithm: u8,
        _: &[u8],
        _: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        assert_eq!(algorithm, 0x02);
        self.mac_calls += 1;
        out.fill(0x3a);
        if self.fail_mac {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.random_calls += 1;
        out.fill(0x55);
        if self.random_calls == self.fail_random_at {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn aes256_cbc(
        &mut self,
        encrypt: bool,
        _: &[u8; 32],
        _: &[u8; 16],
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        if encrypt {
            self.encrypt_calls += 1;
            data.fill(0x66);
            if self.fail_encrypt {
                return Err(CryptoError::Failure);
            }
        } else {
            self.decrypt_calls += 1;
            data.fill(0x42);
            if let Some(pin) = self.new_pin.filter(|_| self.decrypt_calls == 2) {
                data.fill(0x00);
                data[..pin.len()].copy_from_slice(pin);
            }
            if self.fail_decrypt || self.decrypt_calls == self.fail_decrypt_at {
                return Err(CryptoError::Failure);
            }
        }
        Ok(())
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}

#[test]
fn change_refunds_before_new_pin_policy_and_stops_at_each_uncertain_write() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        None,
        Charge,
        ChargeDurable,
        Refund,
        RefundDurable,
        WrongPin,
        OldDecrypt,
        NewDecrypt,
        Policy,
        Replace,
        ReplaceDurable,
    }
    for protocol in [wire::V1, wire::V2] {
        for fault in [
            Fault::None,
            Fault::Charge,
            Fault::ChargeDurable,
            Fault::Refund,
            Fault::RefundDurable,
            Fault::WrongPin,
            Fault::OldDecrypt,
            Fault::NewDecrypt,
            Fault::Policy,
            Fault::Replace,
            Fault::ReplaceDurable,
        ] {
            let mut original = vec![0x42; RP_HASHES];
            original[RETRIES..RP_HASHES].copy_from_slice(&[6, 4, 4, FORCE_CHANGE]);
            if fault == Fault::WrongPin {
                original[0] ^= 0x01;
            }
            let mut storage = Backend {
                record: Some(original.clone()),
                fail_patch_at: match fault {
                    Fault::Charge | Fault::ChargeDurable => 1,
                    Fault::Refund | Fault::RefundDurable => 2,
                    _ => 0,
                },
                fail_patch_durable: matches!(fault, Fault::ChargeDurable | Fault::RefundDurable),
                fail_replace: matches!(fault, Fault::Replace | Fault::ReplaceDurable),
                fail_replace_durable: fault == Fault::ReplaceDurable,
                ..Backend::default()
            };
            let mut crypto = Backend {
                new_pin: Some(if fault == Fault::Policy {
                    b"a"
                } else {
                    b"new-pass8"
                }),
                fail_decrypt_at: match fault {
                    Fault::OldDecrypt => 1,
                    Fault::NewDecrypt => 2,
                    _ => 0,
                },
                ..Backend::default()
            };
            let memory = Backend::default();
            let mut device = Backend::default();
            let mut session = Session::new();
            session.pin_attempts.rejected(7);
            session.pin_attempts.rejected(6);
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            let mut backing = SessionWorkspace::new();
            backing.classic_with(&memory).output.fill(0xee);
            let mut command = Ok(super::super::Command::ClientPin(Parameters {
                protocol,
                subcommand: shared_pin::request::Command::Change as u8,
                agreement: [0x05; 64],
                auth: [0x3a; 32],
                new_pin: [0xaa; 80],
                pin_hash: [0xbb; 32],
                permissions: 0x00,
                rp: [0x00; 254],
                rp_len: 0,
            }));
            let response = session.execute(
                &mut command,
                &mut backing,
                &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut storage,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &memory,
                },
            );
            let workspace = backing.classic_with(&memory);
            let expected = match fault {
                Fault::None => None,
                Fault::WrongPin => Some(Status::PinAuthBlocked),
                Fault::Policy => Some(Status::PinPolicy),
                _ => Some(Status::Other),
            };
            if let Some(expected) = expected {
                assert!(
                    matches!(response, super::super::Response::Error(status) if status == expected),
                    "{protocol} {fault:?}"
                );
                assert!(workspace.output.iter().all(|&byte| byte == 0x00));
            } else {
                assert!(matches!(response, super::super::Response::Prepared(1)));
                assert_eq!(workspace.output[0], 0x00);
            }
            assert!(
                workspace
                    .key
                    .bytes
                    .iter()
                    .chain(workspace.input.iter())
                    .all(|&byte| byte == 0x00)
            );
            let Ok(super::super::Command::ClientPin(parameters)) = command else {
                panic!()
            };
            assert!(
                parameters
                    .auth
                    .iter()
                    .chain(parameters.pin_hash.iter())
                    .chain(parameters.new_pin.iter())
                    .all(|&byte| byte == 0x00)
            );
            let retained = matches!(fault, Fault::Policy | Fault::WrongPin);
            assert_eq!(
                session.pin.token.with_secret(|secret| *secret),
                [if retained { 0x99 } else { 0x00 }; 32]
            );
            assert_eq!(
                session.pin.token.permissions,
                if retained { PERMISSION_CONFIG } else { 0x00 }
            );
            assert_eq!(
                session.pin_attempts.remaining(),
                if fault == Fault::WrongPin {
                    0
                } else if matches!(
                    fault,
                    Fault::Charge | Fault::ChargeDurable | Fault::OldDecrypt
                ) {
                    1
                } else {
                    SESSION_ATTEMPTS
                }
            );
            assert_eq!(
                session.pin.agreement_ready(),
                matches!(fault, Fault::None | Fault::Policy)
            );
            let charged_only = matches!(
                fault,
                Fault::Charge | Fault::ChargeDurable | Fault::WrongPin | Fault::OldDecrypt
            );
            assert_eq!(
                storage.retries_written,
                if charged_only { vec![5] } else { vec![5, 8] }
            );
            assert_eq!(
                crypto.decrypt_calls,
                if matches!(fault, Fault::Charge | Fault::ChargeDurable) {
                    0
                } else if charged_only || matches!(fault, Fault::Refund | Fault::RefundDurable) {
                    1
                } else {
                    2
                }
            );
            let replaced = matches!(fault, Fault::None | Fault::Replace | Fault::ReplaceDurable);
            assert_eq!(storage.replacements.len(), usize::from(replaced));
            let mut expected_record = original;
            if matches!(fault, Fault::None | Fault::ReplaceDurable) {
                expected_record[..PIN_HASH_BYTES]
                    .copy_from_slice(&Sha256::digest(b"new-pass8")[..PIN_HASH_BYTES]);
                expected_record[PIN_LENGTH] = 9;
                expected_record[FLAGS] &= !FORCE_CHANGE;
            }
            expected_record[RETRIES] = match fault {
                Fault::Charge => 6,
                Fault::ChargeDurable | Fault::Refund | Fault::WrongPin | Fault::OldDecrypt => 5,
                _ => 8,
            };
            assert_eq!(
                storage.record.as_ref(),
                Some(&expected_record),
                "{protocol} {fault:?}"
            );
        }
    }
}
impl Device for Backend {
    fn now(&mut self) -> u32 {
        self.now
    }
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn progress(&mut self) -> bool {
        true
    }
    fn led(&mut self, _: bool) {}
}
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        self.wiped.borrow_mut().push(bytes.to_vec());
        bytes.fill(0);
    }
}

#[test]
fn lazy_decapsulation_generates_once_without_exporting_a_response() {
    let mut session = Session::new();
    let mut backing = SessionWorkspace::new();
    let mut crypto = Backend::default();
    let memory = Backend::default();
    let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut Backend::default(),
        crypto: &mut crypto,
        device: &mut Backend::default(),
        memory: &memory,
    };
    let mut w = backing.classic_with(&memory);
    let mut shared = [0; 64];
    for _ in 0..2 {
        session
            .decapsulate(1, &[5; 64], &mut shared, &mut w, &mut p)
            .unwrap();
    }
    assert_eq!(&shared[..32], &Sha256::digest([0x17; 32])[..]);
    assert_eq!(&shared[32..], &shared[..32]);
    drop(p);
    assert_eq!(
        (crypto.generated, crypto.exported, crypto.agreed),
        (1, 0, 2)
    );
    let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut Backend::default(),
        crypto: &mut crypto,
        device: &mut Backend::default(),
        memory: &memory,
    };
    assert_eq!(session.key_agreement(&mut w, &mut p), Ok(81));

    assert!(w.key.bytes.iter().chain(w.input.iter()).all(|&b| b == 0));
    assert_eq!(session.pin.with_private(|private| *private), [7; 32]);
    session.reset(&memory);
    session.key_agreement(&mut w, &mut p).unwrap();
    drop(p);
    assert_eq!((crypto.generated, crypto.exported), (2, 2));
}

#[test]
fn failed_lazy_key_generation_clears_command_workspace_and_authorization() {
    let mut session = Session::new();
    session
        .pin
        .token
        .with_secret_mut(|secret| secret.fill(0x55));
    session.pin.token.permissions = 0x20;
    let mut backing = SessionWorkspace::new();
    let memory = Backend::default();
    let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut Backend::default(),
        crypto: &mut Backend {
            fail_generate: true,
            ..Backend::default()
        },
        device: &mut Backend::default(),
        memory: &memory,
    };
    let w = backing.classic_with(&memory);
    w.output.fill(0xee);
    let mut command = Ok(super::super::Command::ClientPin(Parameters {
        protocol: 1,
        subcommand: 3,
        agreement: [5; 64],
        auth: [0x3a; 32],
        new_pin: [0xaa; 80],
        pin_hash: [0xbb; 32],
        permissions: 0,
        rp: [0; 254],
        rp_len: 0,
    }));
    assert!(matches!(
        session.execute(&mut command, &mut backing, &mut p),
        super::super::Response::Error(Status::Other)
    ));
    let w = backing.classic_with(&memory);
    assert!(!session.pin.agreement_ready());
    assert_eq!(session.pin.with_private(|private| *private), [0; 32]);
    assert_eq!(session.pin.token.with_secret(|secret| *secret), [0; 32]);
    assert_eq!(session.pin.token.permissions, 0);
    assert!(
        w.key
            .bytes
            .iter()
            .chain(w.input.iter())
            .chain(w.output.iter())
            .all(|&b| b == 0)
    );
    let Ok(super::super::Command::ClientPin(cp)) = command else {
        panic!()
    };
    assert!(
        cp.auth
            .iter()
            .chain(cp.new_pin.iter())
            .chain(cp.pin_hash.iter())
            .all(|&b| b == 0)
    );
}

#[test]
fn mac_verification_erases_primitive_output_and_preserves_failure_status() {
    for length in [16, 32] {
        for fail in [false, true] {
            for valid in [false, true] {
                let memory = Backend::default();
                let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut Backend::default(),
                    crypto: &mut Backend {
                        fail_mac: fail,
                        ..Backend::default()
                    },
                    device: &mut Backend::default(),
                    memory: &memory,
                };
                let auth = [if valid { 0x3a } else { 0x3b }; 32];
                assert_eq!(
                    verify_mac(b"key", &auth[..length], b"message", &mut p),
                    if fail {
                        Err(Status::Other)
                    } else if valid {
                        Ok(())
                    } else {
                        Err(Status::PinAuthInvalid)
                    }
                );
                assert_eq!(&*memory.wiped.borrow(), &[vec![0x3a; 64]]);
            }
        }
    }
}

#[test]
fn policy_reads_validate_the_full_record_and_never_cache_flags() {
    let memory = Backend::default();
    let mut storage = Backend::default();
    let mut crypto = Backend::default();
    let mut device = Backend::default();
    let mut read = |storage: &mut Backend| {
        policy(&mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &memory,
        })
    };
    let empty = read(&mut storage).unwrap();
    assert_eq!(
        (empty.retries, empty.pin_length, empty.minimum, empty.flags),
        (8, 0, 4, 0)
    );
    let mut record = vec![0x55; RECORD_BYTES];
    record[RETRIES..RP_HASHES].copy_from_slice(&[7, 8, 6, 4 << RP_HASH_COUNT_SHIFT]);
    for flag in [ALWAYS_UV, FORCE_CHANGE, LONG_RESET, 0] {
        record[FLAGS] = (4 << RP_HASH_COUNT_SHIFT) | flag;
        storage.record = Some(record.clone());
        let value = read(&mut storage).unwrap();
        assert_eq!(
            (value.retries, value.pin_length, value.minimum, value.flags),
            (7, 8, 6, record[FLAGS])
        );
    }
    storage.fail_read = true;
    assert!(matches!(read(&mut storage), Err(Status::Other)));
    storage.fail_read = false;
    for (length, field, byte) in [
        (20, FLAGS, 8),
        (148, FLAGS, 0),
        (20, RETRIES, 9),
        (20, PIN_LENGTH, 1),
        (20, MIN_PIN_LENGTH, 3),
    ] {
        let mut record = vec![0; length];
        record[RETRIES..RP_HASHES].copy_from_slice(&[8, 8, 4, 0]);
        record[field] = byte;
        storage.record = Some(record);
        assert!(matches!(read(&mut storage), Err(Status::Other)));
    }
    assert!(
        memory
            .wiped
            .borrow()
            .iter()
            .all(|bytes| bytes.len() == RECORD_BYTES)
    );
}

#[test]
fn cbc_and_rng_failures_preserve_durable_charge_and_erase_session_outputs() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        None,
        Charge,
        ChargeDurable,
        Restore,
        RestoreDurable,
        WrongPin,
        Decrypt,
        TokenRandom,
        IvRandom,
        Encrypt,
        RpHash,
    }
    for protocol in [wire::V1, wire::V2] {
        for fault in [
            Fault::None,
            Fault::Charge,
            Fault::ChargeDurable,
            Fault::Restore,
            Fault::RestoreDurable,
            Fault::WrongPin,
            Fault::Decrypt,
            Fault::TokenRandom,
            Fault::IvRandom,
            Fault::Encrypt,
            Fault::RpHash,
        ] {
            if protocol == wire::V1 && fault == Fault::IvRandom {
                continue;
            }
            let mut record = vec![0x42; RP_HASHES];
            record[RETRIES..RP_HASHES].copy_from_slice(&[8, 4, 4, 0x00]);
            if fault == Fault::WrongPin {
                record[0] ^= 0x01;
            }
            let mut storage = Backend {
                record: Some(record),
                fail_patch_at: match fault {
                    Fault::Charge | Fault::ChargeDurable => 1,
                    Fault::Restore | Fault::RestoreDurable => 2,
                    _ => 0,
                },
                fail_patch_durable: matches!(fault, Fault::ChargeDurable | Fault::RestoreDurable),
                ..Backend::default()
            };
            let mut crypto = Backend {
                fail_decrypt: fault == Fault::Decrypt,
                fail_encrypt: fault == Fault::Encrypt,
                fail_sha_at: if fault == Fault::RpHash {
                    // Protocol 1 hashes the ECDH output before the RP hash.
                    1 + usize::from(protocol == wire::V1)
                } else {
                    0
                },
                fail_random_at: if fault == Fault::TokenRandom {
                    1
                } else if fault == Fault::IvRandom {
                    2
                } else {
                    0
                },
                ..Backend::default()
            };
            let memory = Backend::default();
            let mut device = Backend::default();
            let mut session = Session::new();
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            let mut backing = SessionWorkspace::new();
            let w = backing.classic_with(&memory);
            w.output.fill(0xee);
            let mut rp = [0x00; 254];
            rp[..11].copy_from_slice(b"example.com");
            let mut command = Ok(super::super::Command::ClientPin(Parameters {
                protocol,
                subcommand: wire::GET_TOKEN_PERMISSIONS,
                agreement: [0x05; 64],
                auth: [0x3a; 32],
                new_pin: [0xaa; 80],
                pin_hash: [0xbb; 32],
                permissions: wire::PERMISSION_CREDENTIALS,
                rp,
                rp_len: 11,
            }));
            let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            };
            let response = session.execute(&mut command, &mut backing, &mut p);
            let w = backing.classic_with(&memory);
            if fault == Fault::None {
                let length = if protocol == wire::V1 { 32 } else { 48 };
                assert!(matches!(response, super::super::Response::Prepared(n) if n == 5 + length));
                assert_eq!(&w.output[..5], &[0x00, 0xa1, 0x02, 0x58, length as u8]);
                let prefix = if protocol == wire::V1 { 0 } else { 16 };
                assert_eq!(&w.output[5..5 + prefix], &[0x55; 16][..prefix]);
                assert_eq!(&w.output[5 + prefix..5 + length], &[0x66; 32]);
                assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x55; 32]);
                assert_eq!(session.pin.token.permissions, wire::PERMISSION_CREDENTIALS);
                assert_eq!(
                    session.pin.token.rp_id().unwrap().as_slice(),
                    Sha256::digest(b"example.com").as_slice()
                );
            } else {
                let expected = if fault == Fault::WrongPin {
                    Status::PinInvalid
                } else {
                    Status::Other
                };
                assert!(
                    matches!(response, super::super::Response::Error(status) if status == expected)
                );
                // A wrong proof charges attempts and invalidates agreement,
                // while Other also resets prior token authority in execute.
                let retained = fault == Fault::WrongPin;
                assert_eq!(
                    session.pin.token.with_secret(|secret| *secret),
                    [if retained { 0x99 } else { 0x00 }; 32]
                );
                assert_eq!(
                    session.pin.token.permissions,
                    if retained { PERMISSION_CONFIG } else { 0x00 }
                );
                assert!(session.pin.token.rp_id().is_none());
                assert_eq!(
                    session.pin_attempts.remaining(),
                    if retained {
                        SESSION_ATTEMPTS - 1
                    } else {
                        SESSION_ATTEMPTS
                    }
                );
                assert_eq!(session.pin.with_private(|private| *private), [0x00; 32]);
                assert!(!session.pin.agreement_ready());
                assert!(w.output.iter().all(|&byte| byte == 0x00));
            }
            assert!(
                w.key
                    .bytes
                    .iter()
                    .chain(w.input.iter())
                    .all(|&byte| byte == 0x00)
            );
            let Ok(super::super::Command::ClientPin(cp)) = command else {
                panic!()
            };
            assert!(
                cp.auth
                    .iter()
                    .chain(cp.new_pin.iter())
                    .chain(cp.pin_hash.iter())
                    .all(|&byte| byte == 0x00)
            );
            drop(p);
            let expected_retries = match fault {
                Fault::Charge => 8,
                Fault::ChargeDurable | Fault::Decrypt | Fault::WrongPin | Fault::Restore => 7,
                _ => 8,
            };
            assert_eq!(storage.record.as_ref().unwrap()[RETRIES], expected_retries);
            assert_eq!(
                storage.retries_written,
                if matches!(
                    fault,
                    Fault::Charge | Fault::ChargeDurable | Fault::Decrypt | Fault::WrongPin
                ) {
                    vec![7]
                } else {
                    vec![7, 8]
                }
            );
            assert_eq!(
                crypto.decrypt_calls,
                usize::from(!matches!(fault, Fault::Charge | Fault::ChargeDurable))
            );
            let random_calls = match fault {
                Fault::Charge
                | Fault::ChargeDurable
                | Fault::Restore
                | Fault::RestoreDurable
                | Fault::WrongPin
                | Fault::Decrypt => 0,
                Fault::TokenRandom => 1,
                _ if protocol == wire::V1 => 1,
                _ => 2,
            };
            assert_eq!(crypto.random_calls, random_calls);
            assert_eq!(
                crypto.encrypt_calls,
                usize::from(matches!(
                    fault,
                    Fault::None | Fault::Encrypt | Fault::RpHash
                ))
            );
        }
    }
}

#[test]
fn token_admission_preserves_primitive_order_and_refreshes_only_successful_use() {
    let memory = Backend::default();
    let rp = [0x51; 32];
    for protocol in [0x00, wire::V1, wire::V2, 0x03] {
        for length in [15, 16, 31, 32, 33] {
            for granted in [0x00, 0x01, 0x02, 0x03] {
                for required in [0x00, 0x01, 0x03] {
                    for bound in [None, Some(rp), Some([0x52; 32])] {
                        for fail_mac in [false, true] {
                            let mut session = Session::new();
                            session.pin_attempts.reset();
                            session
                                .pin
                                .token
                                .with_secret_mut(|secret| secret.fill(0x61));
                            session.pin.token.permissions = granted;
                            session.pin.token.issued = 0;
                            session.pin.token.last_used = 1;
                            if let Some(bound) = bound {
                                session.pin.token.bind_rp(Some(bound));
                            }
                            let mut crypto = Backend {
                                fail_mac,
                                ..Backend::default()
                            };
                            let mut device = Backend {
                                now: 7,
                                ..Backend::default()
                            };
                            let mut storage = Backend::default();
                            let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                                storage: &mut storage,
                                crypto: &mut crypto,
                                device: &mut device,
                                memory: &memory,
                            };
                            let admitted = matches!(protocol, wire::V1 | wire::V2)
                                && length == wire::auth_bytes(protocol)
                                && required != 0x00
                                && granted & required == required
                                && bound.is_none_or(|bound| bound == rp);
                            let expected = if !admitted {
                                Err(Status::PinAuthInvalid)
                            } else if fail_mac {
                                Err(Status::Other)
                            } else {
                                Ok(())
                            };
                            assert_eq!(
                                session.authorize(
                                    protocol,
                                    &[0x3a; 33][..length],
                                    b"message",
                                    required,
                                    Some(&rp),
                                    &mut platform
                                ),
                                expected
                            );
                            assert_eq!(crypto.mac_calls, usize::from(admitted));
                            assert_eq!(
                                session.pin.token.last_used,
                                if expected.is_ok() { 7 } else { 1 }
                            );
                            assert_eq!(session.pin.token.rp_id().is_some(), bound.is_some());
                            assert_eq!(session.pin.token.permissions, granted);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn public_generation_and_export_failures_do_not_publish_or_retain_authority() {
    for fail_generate in [false, true] {
        for fail_export in [false, true] {
            let memory = Backend::default();
            let mut crypto = Backend {
                fail_generate,
                fail_export,
                ..Backend::default()
            };
            let mut storage = Backend::default();
            let mut device = Backend::default();
            let mut session = Session::new();
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            let mut backing = SessionWorkspace::new();
            let workspace = backing.classic_with(&memory);
            workspace.output.fill(0xee);
            let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            };
            let response = session.execute(
                &mut Ok(super::super::Command::GetKeyAgreement),
                &mut backing,
                &mut platform,
            );
            let workspace = backing.classic_with(&memory);
            let failed = fail_generate || fail_export;
            if failed {
                assert!(matches!(
                    response,
                    super::super::Response::Error(Status::Other)
                ));
                assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x00; 32]);
                assert_eq!(session.pin.token.permissions, 0x00);
                assert!(workspace.output.iter().all(|byte| *byte == 0x00));
            } else {
                assert!(matches!(response, super::super::Response::Prepared(81)));
                assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x99; 32]);
                assert_eq!(session.pin.token.permissions, PERMISSION_CONFIG);
            }
            assert_eq!(session.pin.agreement_ready(), !failed);
            assert!(
                workspace
                    .key
                    .bytes
                    .iter()
                    .chain(workspace.input.iter())
                    .all(|byte| *byte == 0x00)
            );
            assert_eq!(crypto.generated, 1);
            assert_eq!(crypto.exported, usize::from(!fail_generate));
        }
    }
}

#[test]
fn ecdh_failure_and_short_output_precede_internal_protocol_admission_and_kdf() {
    for fail_agree in [false, true] {
        for agreed_bytes in [31, 32, 33] {
            let memory = Backend::default();
            let mut crypto = Backend {
                fail_agree,
                agreed_bytes: Some(agreed_bytes),
                ..Backend::default()
            };
            let mut record = vec![0x42; RP_HASHES];
            record[RETRIES..RP_HASHES].copy_from_slice(&[8, 4, 4, 0x00]);
            let mut storage = Backend {
                record: Some(record),
                ..Backend::default()
            };
            let mut device = Backend::default();
            let mut session = Session::new();
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            let mut backing = SessionWorkspace::new();
            let workspace = backing.classic_with(&memory);
            workspace.output.fill(0xee);
            let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            };
            // Internal construction bypasses wire admission to observe the
            // established first-error order after validated peer exchange.
            let mut command = Ok(super::super::Command::ClientPin(Parameters {
                protocol: 0x03,
                subcommand: wire::GET_TOKEN_PERMISSIONS,
                agreement: [0x05; 64],
                auth: [0x3a; 32],
                new_pin: [0xaa; 80],
                pin_hash: [0xbb; 32],
                permissions: wire::PERMISSION_CREDENTIALS,
                rp: [0x00; 254],
                rp_len: 0,
            }));
            let response = session.execute(&mut command, &mut backing, &mut platform);
            let workspace = backing.classic_with(&memory);
            let reset = !fail_agree && agreed_bytes != 32;
            let expected = if reset {
                Status::Other
            } else {
                Status::InvalidParameter
            };
            assert!(
                matches!(response, super::super::Response::Error(status) if status == expected)
            );
            assert_eq!(session.pin.agreement_ready(), !reset);
            assert_eq!(
                session.pin.token.with_secret(|secret| *secret),
                [if reset { 0x00 } else { 0x99 }; 32]
            );
            assert_eq!(
                session.pin.token.permissions,
                if reset { 0x00 } else { PERMISSION_CONFIG }
            );
            assert!(
                workspace
                    .key
                    .bytes
                    .iter()
                    .chain(workspace.input.iter())
                    .chain(workspace.output.iter())
                    .all(|byte| *byte == 0x00)
            );
            let Ok(super::super::Command::ClientPin(parameters)) = command else {
                panic!()
            };
            assert!(
                parameters
                    .auth
                    .iter()
                    .chain(parameters.new_pin.iter())
                    .chain(parameters.pin_hash.iter())
                    .all(|byte| *byte == 0x00)
            );
            assert_eq!(crypto.generated, 1);
            assert_eq!(crypto.agreed, 1);
            assert_eq!(crypto.exported, 0);
            assert_eq!(crypto.sha_calls, 0);
            assert_eq!(crypto.mac_calls, 0);
            assert!(storage.retries_written.is_empty());
            assert_eq!(storage.record.as_ref().unwrap()[RETRIES], 8);
        }
    }
}

use super::super::client_pin::admission_cases as point_admission_cases;

#[test]
fn parsed_point_rejection_never_reaches_kdf_decrypt_retry_or_token_commit() {
    for point in point_admission_cases::invalid_points() {
        for (bytes, schema_error) in point_admission_cases::legacy_token_cases_for_point(&point) {
            let memory = Backend::default();
            let mut record = vec![0x42; RP_HASHES];
            record[RETRIES..RP_HASHES].copy_from_slice(&[8, 4, 4, 0x00]);
            let mut storage = Backend {
                record: Some(record.clone()),
                ..Backend::default()
            };
            let mut crypto = Backend {
                fail_agree: true,
                expected_peer: Some(point),
                ..Backend::default()
            };
            let mut device = Backend::default();
            let mut session = Session::new();
            session.pin.commit_agreement();
            session.pin.with_private_mut(|private| private.fill(0x07));
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            let agreement = session.pin.with_private(|private| *private);
            let attempts = session.pin_attempts.remaining();
            let mut backing = SessionWorkspace::new();
            let workspace = backing.classic_with(&memory);
            workspace.input.fill(0xee);
            workspace.output.fill(0xee);
            workspace.key.bytes.fill(0xee);
            let mut parser = super::super::client_pin::Parser::new();
            parser.consume(&bytes);
            let mut command = parser.finish();
            assert_eq!(
                command.as_ref().err().map(|status| *status as u8),
                schema_error
            );
            let response = session.execute(
                &mut command,
                &mut backing,
                &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut storage,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &memory,
                },
            );
            let workspace = backing.classic_with(&memory);
            let expected = schema_error.unwrap_or(Status::InvalidParameter as u8);
            assert!(
                matches!(response, super::super::Response::Error(status) if status as u8 == expected)
            );
            assert_eq!(session.pin.with_private(|private| *private), agreement);
            assert!(session.pin.agreement_ready());
            assert_eq!(session.pin_attempts.remaining(), attempts);
            assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x99; 32]);
            assert_eq!(session.pin.token.permissions, PERMISSION_CONFIG);
            // Session::execute enters the credential workspace owner only for
            // admitted ClientPIN commands. Parse failures leave caller-owned
            // staging untouched; transport/runtime cleanup owns that backing.
            let untouched = if schema_error.is_some() { 0xee } else { 0x00 };
            assert!(
                workspace
                    .input
                    .iter()
                    .chain(workspace.output.iter())
                    .chain(workspace.key.bytes.iter())
                    .all(|byte| *byte == untouched)
            );
            assert_eq!(storage.record.as_ref(), Some(&record));
            assert!(storage.retries_written.is_empty());
            assert_eq!(storage.reads, usize::from(schema_error.is_none()));
            assert_eq!(crypto.agreed, usize::from(schema_error.is_none()));
            assert_eq!(
                (
                    crypto.generated,
                    crypto.exported,
                    crypto.sha_calls,
                    crypto.mac_calls,
                    crypto.decrypt_calls,
                    crypto.encrypt_calls,
                    crypto.random_calls
                ),
                (0, 0, 0, 0, 0, 0, 0)
            );
            if let Ok(super::super::Command::ClientPin(parameters)) = command {
                assert!(
                    parameters
                        .auth
                        .iter()
                        .chain(parameters.new_pin.iter())
                        .chain(parameters.pin_hash.iter())
                        .all(|byte| *byte == 0x00)
                );
            }
        }
    }
}

#[test]
fn wrong_pin_retains_standard_token_but_third_mismatch_blocks_its_use() {
    for protocol in [wire::V1, wire::V2] {
        for initial_retries in [3, MAX_RETRIES] {
            let mut record = vec![0x42; RP_HASHES];
            record[0] ^= 0x01;
            record[RETRIES..RP_HASHES].copy_from_slice(&[initial_retries, 4, 4, 0x00]);
            let mut storage = Backend {
                record: Some(record),
                ..Backend::default()
            };
            let mut crypto = Backend::default();
            let memory = Backend::default();
            let mut device = Backend::default();
            let mut session = Session::new();
            session
                .pin
                .token
                .with_secret_mut(|secret| secret.fill(0x99));
            session.pin.token.permissions = PERMISSION_CONFIG;
            session.pin.token.bind_rp(Some([0x5a; 32]));
            let mut backing = SessionWorkspace::new();
            let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut storage,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            };
            for attempt in 1..=3 {
                let mut command = Ok(super::super::Command::ClientPin(Parameters {
                    protocol,
                    subcommand: wire::GET_TOKEN_PERMISSIONS,
                    agreement: [0x05; 64],
                    auth: [0x3a; 32],
                    new_pin: [0x00; 80],
                    pin_hash: [0xbb; 32],
                    permissions: wire::PERMISSION_CREDENTIALS,
                    rp: [0x00; 254],
                    rp_len: 0,
                }));
                let response = session.execute(&mut command, &mut backing, &mut platform);
                let status = if attempt == initial_retries {
                    Status::PinBlocked
                } else if attempt == 3 {
                    Status::PinAuthBlocked
                } else {
                    Status::PinInvalid
                };
                assert!(
                    matches!(response, super::super::Response::Error(error) if error == status)
                );
                assert!(!session.pin.agreement_ready());
                assert_eq!(session.pin.with_private(|private| *private), [0x00; 32]);
                assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x99; 32]);
                assert_eq!(session.pin.token.permissions, PERMISSION_CONFIG);
                assert_eq!(
                    session.pin.token.rp_id().copied().unwrap_or([0x00; 32]),
                    [0x5a; 32]
                );
                assert!(session.pin.token.rp_id().is_some());
                assert_eq!(
                    (session.pin.token.issued, session.pin.token.last_used),
                    (0, 0)
                );
                assert_eq!(platform.crypto.generated, usize::from(attempt));
                let result = session.authorize(
                    protocol,
                    &[0x3a; 32][..wire::auth_bytes(protocol)],
                    &[0x01],
                    PERMISSION_CONFIG,
                    Some(&[0x5a; 32]),
                    &mut platform,
                );
                assert_eq!(
                    result,
                    if attempt < 3 {
                        Ok(())
                    } else {
                        Err(Status::PinAuthBlocked)
                    }
                );
            }
            // Explicit agreement is allowed while blocked. Early ClientPIN
            // admission must preserve that key and never run ECDH or charge.
            session
                .agreement_key(&mut backing.classic_with(&memory), &mut platform)
                .unwrap();
            let agreed = platform.crypto.agreed;
            let charged = platform.storage.retries_written.len();
            let mut parameters = Parameters {
                protocol,
                subcommand: wire::GET_TOKEN_PERMISSIONS,
                agreement: [0x05; 64],
                auth: [0x3a; 32],
                new_pin: [0x00; 80],
                pin_hash: [0xbb; 32],
                permissions: wire::PERMISSION_CREDENTIALS,
                rp: [0x00; 254],
                rp_len: 0,
            };
            let result = session.client_pin(
                &mut parameters,
                &mut backing.classic_with(&memory),
                &mut platform,
            );
            assert_eq!(
                result,
                Err(if initial_retries == 3 {
                    Status::PinBlocked
                } else {
                    Status::PinAuthBlocked
                })
            );
            assert!(session.pin.agreement_ready());
            assert_eq!(session.pin.with_private(|private| *private), [0x07; 32]);
            assert_eq!(platform.crypto.agreed, agreed);
            assert_eq!(platform.storage.retries_written.len(), charged);

            // Connection cleanup erases both secrets without refunding the
            // power-cycle allowance held outside the shared connection owner.
            session.reset(&memory);
            assert!(session.pin_attempts.blocked());
            assert!(!session.pin.agreement_ready());
            assert_eq!(session.pin.with_private(|private| *private), [0x00; 32]);
            assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x00; 32]);
            assert_eq!(session.pin.token.permissions, 0x00);
            assert!(session.pin.token.rp_id().is_none());
            assert_eq!(
                (session.pin.token.issued, session.pin.token.last_used),
                (0, 0)
            );
            assert_eq!(
                session.client_pin(
                    &mut parameters,
                    &mut backing.classic_with(&memory),
                    &mut platform,
                ),
                result
            );
            assert_eq!(platform.crypto.agreed, agreed);
            assert_eq!(platform.storage.retries_written.len(), charged);
        }
    }
}
