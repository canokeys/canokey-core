// SPDX-License-Identifier: Apache-2.0
//! Inject a failure at every durable reset mutation, including ADMIN PIN recovery.
extern crate std;
use super::*;
use crate::ports::{Crypto, CryptoError, Device, Memory, Record, Storage, StorageError};
use std::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Replace(Record),
    Patch(Record),
    Remove(Record),
    Resize(Record),
}
#[derive(Default)]
struct Store {
    mutations: Vec<Mutation>,
    fail_at: Option<usize>,
}
impl Store {
    fn mutate(&mut self, operation: Mutation) -> Result<(), StorageError> {
        self.mutations.push(operation);
        if self.fail_at == Some(self.mutations.len() - 1) {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
}
impl Storage for Store {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::Missing)
    }
    fn replace(&mut self, record: Record, _: &[u8]) -> Result<(), StorageError> {
        self.mutate(Mutation::Replace(record))
    }
    fn replace_at(&mut self, record: Record, _: u32, _: &[u8]) -> Result<(), StorageError> {
        self.mutate(Mutation::Patch(record))
    }
    fn remove(&mut self, record: Record) -> Result<(), StorageError> {
        self.mutate(Mutation::Remove(record))
    }
    fn resize(&mut self, record: Record, _: u32) -> Result<(), StorageError> {
        self.mutate(Mutation::Resize(record))
    }
}
struct Random;
impl Crypto for Random {
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        panic!("reset must not calculate credential MACs")
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        panic!("reset must not calculate PASS HMACs")
    }
    fn random(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        output.fill(0x5a);
        Ok(())
    }
}
struct NoTouch;
impl Device for NoTouch {
    fn serial(&mut self, _: &mut [u8; 4]) {
        panic!("reset must not query identity")
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        panic!("reset flow must not request presence")
    }
    fn progress(&mut self) -> bool {
        panic!("reset flow must not yield")
    }
    fn led(&mut self, _: bool) {}
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

fn execute(fail_at: Option<usize>) -> (bool, Vec<Mutation>) {
    let mut storage = Store::default();
    let mut pass = Pass::new();
    pass.install(&mut storage, &Wipe).unwrap();
    storage.mutations.clear();
    storage.fail_at = fail_at;
    let result = run(
        Some(&mut pass),
        &mut crate::applets::ctap::Applet::new(),
        &mut SessionWorkspace::new(),
        &mut Platform {
            storage: &mut storage,
            crypto: &mut Random,
            device: &mut NoTouch,
            memory: &Wipe,
        },
    );
    (result.is_ok(), storage.mutations)
}

#[test]
fn every_failed_mutation_stops_reset_before_later_records_or_pin_recovery() {
    let (success, complete) = execute(None);
    assert!(success);
    assert_eq!(
        complete.first(),
        Some(&Mutation::Replace(Record::NdefMessage))
    );
    assert_eq!(complete.last(), Some(&Mutation::Replace(Record::AdminPin)));
    let phase_starts = [
        Mutation::Replace(Record::NdefMessage),
        Mutation::Remove(Record::CtapMaster),
        Mutation::Patch(Record::Pass),
        Mutation::Replace(Record::OathRecords),
        Mutation::Replace(Record::PgpState),
        Mutation::Replace(Record::PivProvision),
        Mutation::Replace(Record::AdminPin),
    ]
    .map(|operation| {
        complete
            .iter()
            .position(|entry| *entry == operation)
            .unwrap()
    });
    assert!(phase_starts.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!complete.contains(&Mutation::Remove(Record::CtapAttestationKey)));
    assert!(!complete.contains(&Mutation::Remove(Record::CtapCertificate)));
    for index in 0..complete.len() {
        let (success, mutations) = execute(Some(index));
        assert!(!success, "failure at mutation {index} was ignored");
        assert_eq!(
            mutations,
            complete[..=index],
            "reset continued after mutation {index}"
        );
        if index + 1 < complete.len() {
            assert!(!mutations.contains(&Mutation::Replace(Record::AdminPin)));
        }
    }
}
