// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::{ports::*, runtime::workspace::SessionWorkspace};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, vec, vec::Vec};

#[derive(Default)]
struct Backend {
    generated: usize,
    exported: usize,
    agreed: usize,
    fail_generate: bool,
    fail_mac: bool,
    fail_read: bool,
    record: Option<Vec<u8>>,
    wiped: RefCell<Vec<Vec<u8>>>,
}
impl Storage for Backend {
    fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
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
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        unreachable!()
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
                Ok(64)
            }
            KeyOperation::Agree => {
                self.agreed += 1;
                assert_eq!(&key.bytes[..32], &[7; 32]);
                assert_eq!(input, [5; 64]);
                out[..32].fill(0x17);
                Ok(32)
            }
            _ => unreachable!(),
        }
    }
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&Sha256::digest(input));
        Ok(())
    }
    fn mac(
        &mut self,
        algorithm: u8,
        _: &[u8],
        _: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        assert_eq!(algorithm, 2);
        out.fill(0x3a);
        if self.fail_mac {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
impl Device for Backend {
    fn now(&mut self) -> u32 {
        0
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
    assert_eq!(session.agreement, [7; 32]);
    session.reset(&memory);
    session.key_agreement(&mut w, &mut p).unwrap();
    drop(p);
    assert_eq!((crypto.generated, crypto.exported), (2, 2));
}

#[test]
fn failed_lazy_key_generation_clears_command_workspace_and_authorization() {
    let mut session = Session::new();
    session.token.fill(0x55);
    session.permissions = 0x20;
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
    let mut w = backing.classic_with(&memory);
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
        session.execute(&mut command, &mut w, &mut p),
        super::super::Response::Error(Status::Other)
    ));
    assert!(!session.agreement_ready);
    assert_eq!(session.agreement, [0; 32]);
    assert_eq!(session.token, [0; 32]);
    assert_eq!(session.permissions, 0);
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
