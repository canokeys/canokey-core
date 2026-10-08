// SPDX-License-Identifier: Apache-2.0
//! ADMIN owns authorization; the CTAP certificate transaction owns publication.
extern crate std;
use super::*;
use crate::{
    ports::{Crypto, CryptoError, Device, Memory, Record, Storage, StorageError},
    runtime::workspace::SessionWorkspace,
};
use std::{vec, vec::Vec};

// Opaque fragments exercise staging rather than certificate parsing.
const FRAGMENT: &[u8] = b"certificate fragment";
const PREVIOUS: &[u8] = b"previous certificate";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Begin,
    Append,
    Commit,
    Abort,
}
struct Stage {
    calls: Vec<Operation>,
    fail: Option<Operation>,
    pending: Vec<u8>,
    committed: Vec<u8>,
}
impl Stage {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail: None,
            pending: Vec::new(),
            committed: PREVIOUS.to_vec(),
        }
    }
    fn call(&mut self, operation: Operation) -> Result<(), StorageError> {
        self.calls.push(operation);
        if self.fail == Some(operation) {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
}
impl Storage for Stage {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        panic!("staging must not load records")
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        panic!("staging must publish through commit")
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.call(Operation::Begin)?;
        self.pending.clear();
        Ok(())
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.call(Operation::Append)?;
        self.pending.extend_from_slice(bytes);
        Ok(())
    }
    fn stage_commit(&mut self, record: Record) -> Result<(), StorageError> {
        assert_eq!(record, Record::CtapCertificate);
        self.call(Operation::Commit)?;
        self.committed = core::mem::take(&mut self.pending);
        Ok(())
    }
    fn stage_abort(&mut self) {
        self.calls.push(Operation::Abort);
        self.pending.clear();
    }
}
struct NoCrypto;
impl Crypto for NoCrypto {
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        panic!("staging must not request randomness")
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        panic!("staging must not calculate MACs")
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        panic!("staging must not calculate PASS HMACs")
    }
}
struct NoTouch;
impl Device for NoTouch {
    fn serial(&mut self, _: &mut [u8; 4]) {
        panic!("staging must not query identity")
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        panic!("staging must not request presence")
    }
    fn progress(&mut self) -> bool {
        panic!("staging must not yield")
    }
    fn led(&mut self, _: bool) {}
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
struct Fixture {
    storage: Stage,
    crypto: NoCrypto,
    device: NoTouch,
}
impl Fixture {
    fn new() -> Self {
        Self {
            storage: Stage::new(),
            crypto: NoCrypto,
            device: NoTouch,
        }
    }
    fn platform(&mut self) -> Platform<'_, impl crate::ports::Backends> {
        Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut self.storage,
            crypto: &mut self.crypto,
            device: &mut self.device,
            memory: &Wipe,
        }
    }
}
fn header() -> Header {
    Header {
        cla: 0,
        ins: INS_PROVISION_ATTESTATION,
        p1: 0,
        p2: 0,
    }
}

#[test]
fn authorized_complete_certificate_publishes_once_without_abort() {
    let mut fixture = Fixture::new();
    let mut admin = Admin::new();
    let mut grants = Grants { admin: true };
    let mut workspace = SessionWorkspace::new();
    let mut p = fixture.platform();
    admin.begin(header(), &grants, &mut p).unwrap();
    admin
        .consume(FRAGMENT, &mut workspace.classic_with(&Wipe), &mut p)
        .unwrap();
    assert!(matches!(
        admin.finish(
            header(),
            0,
            &mut grants,
            None,
            &mut p,
            &mut workspace.classic_with(&Wipe)
        ),
        Ok(Action::Response(0))
    ));
    admin.abort_transaction(&mut p);
    assert_eq!(fixture.storage.committed, FRAGMENT);
    assert_eq!(
        fixture.storage.calls,
        vec![Operation::Begin, Operation::Append, Operation::Commit]
    );
}

#[test]
fn cancellation_and_failed_publication_keep_previous_certificate() {
    for commit_failure in [false, true] {
        let mut fixture = Fixture::new();
        let mut admin = Admin::new();
        let mut grants = Grants { admin: true };
        let mut workspace = SessionWorkspace::new();
        let mut p = fixture.platform();
        admin.begin(header(), &grants, &mut p).unwrap();
        admin
            .consume(FRAGMENT, &mut workspace.classic_with(&Wipe), &mut p)
            .unwrap();
        drop(p);
        if commit_failure {
            fixture.storage.fail = Some(Operation::Commit);
        }
        let mut p = fixture.platform();
        if commit_failure {
            assert!(matches!(
                admin.finish(
                    header(),
                    0,
                    &mut grants,
                    None,
                    &mut p,
                    &mut workspace.classic_with(&Wipe)
                ),
                Err(Sw::UNABLE_TO_PROCESS)
            ));
        } else {
            admin.cancel_command(&mut workspace.classic_with(&Wipe), &mut p);
        }
        admin.abort_transaction(&mut p);
        assert_eq!(fixture.storage.committed, PREVIOUS);
        assert!(fixture.storage.pending.is_empty());
        assert_eq!(
            fixture
                .storage
                .calls
                .iter()
                .filter(|&&op| op == Operation::Abort)
                .count(),
            1
        );
        assert_eq!(
            fixture.storage.calls.contains(&Operation::Commit),
            commit_failure
        );
    }
}

#[test]
fn authorization_bounds_and_append_failure_never_publish() {
    for append_failure in [false, true] {
        let mut fixture = Fixture::new();
        let mut admin = Admin::new();
        let mut workspace = SessionWorkspace::new();
        let mut p = fixture.platform();
        assert_eq!(
            admin.begin(header(), &Grants::default(), &mut p),
            Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
        );
        drop(p);
        assert!(fixture.storage.calls.is_empty());
        if append_failure {
            fixture.storage.fail = Some(Operation::Append);
        }
        let mut p = fixture.platform();
        admin
            .begin(header(), &Grants { admin: true }, &mut p)
            .unwrap();
        let oversized = [0; crate::applets::ctap::provision::CERT_LIMIT + 1];
        let bytes = if append_failure { FRAGMENT } else { &oversized };
        assert_eq!(
            admin.consume(bytes, &mut workspace.classic_with(&Wipe), &mut p),
            Err(if append_failure {
                Sw::UNABLE_TO_PROCESS
            } else {
                Sw::WRONG_LENGTH
            })
        );
        admin.abort_transaction(&mut p);
        assert_eq!(fixture.storage.committed, PREVIOUS);
        assert!(!fixture.storage.calls.contains(&Operation::Commit));
        assert_eq!(
            fixture.storage.calls.contains(&Operation::Append),
            append_failure
        );
    }
}
