// SPDX-License-Identifier: Apache-2.0
extern crate std;
use crate::{
    applets::openpgp::protocol::OpenPgp,
    ports::*,
    runtime::workspace::{SessionWorkspace, Workspace},
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Default)]
struct Disk {
    records: BTreeMap<u8, Vec<u8>>,
    staged: Vec<u8>,
    reads: usize,
    writes: usize,
    fail_read: bool,
    fail_write: Option<Record>,
    applied: bool,
}
impl Disk {
    fn write(
        &mut self,
        id: Record,
        offset: usize,
        input: &[u8],
        truncate: bool,
    ) -> Result<(), StorageError> {
        self.writes += 1;
        let failed = self.fail_write == Some(id);
        if failed {
            self.fail_write = None;
        }
        if !failed || self.applied {
            let bytes = self.records.entry(id.id()).or_default();
            if truncate {
                bytes.clear();
            }
            bytes.resize(bytes.len().max(offset + input.len()), 0);
            bytes[offset..offset + input.len()].copy_from_slice(input);
        }
        if failed {
            Err(StorageError::Unavailable)
        } else {
            Ok(())
        }
    }
}
impl Storage for Disk {
    fn size(&mut self, id: Record) -> Result<u32, StorageError> {
        self.records
            .get(&id.id())
            .map(|b| b.len() as u32)
            .ok_or(StorageError::Missing)
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.staged.clear();
        Ok(())
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.staged.extend_from_slice(bytes);
        Ok(())
    }
    fn stage_commit(&mut self, id: Record) -> Result<(), StorageError> {
        let bytes = std::mem::take(&mut self.staged);
        self.replace(id, &bytes)
    }
    fn stage_abort(&mut self) {
        self.staged.clear();
    }

    fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        self.reads += 1;
        if self.fail_read {
            return Err(StorageError::Unavailable);
        }
        let bytes = self.records.get(&id.id()).ok_or(StorageError::Missing)?;
        if bytes.len() > out.len() {
            return Err(StorageError::Unavailable);
        }
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn read_at(&mut self, id: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        self.reads += 1;
        if self.fail_read {
            return Err(StorageError::Unavailable);
        }
        let bytes = self.records.get(&id.id()).ok_or(StorageError::Missing)?;
        out.copy_from_slice(
            bytes
                .get(offset as usize..offset as usize + out.len())
                .ok_or(StorageError::Unavailable)?,
        );
        Ok(())
    }
    fn replace(&mut self, id: Record, input: &[u8]) -> Result<(), StorageError> {
        self.write(id, 0, input, true)
    }
    fn replace_at(&mut self, id: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        self.write(id, offset as usize, input, false)
    }
}
struct Services;
impl Crypto for Services {
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
impl Device for Services {
    fn serial(&mut self, out: &mut [u8; 4]) {
        out.fill(0);
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn progress(&mut self) -> bool {
        true
    }
    fn led(&mut self, _: bool) {}
}
impl Memory for Services {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
struct Card {
    app: OpenPgp,
    workspace: SessionWorkspace,
    disk: Disk,
}
impl Card {
    fn with<T>(
        &mut self,
        f: impl FnOnce(&mut OpenPgp, &mut Workspace, &mut Platform<'_>) -> T,
    ) -> T {
        let mut crypto = Services;
        let mut device = Services;
        let mut platform = Platform {
            storage: &mut self.disk,
            crypto: &mut crypto,
            device: &mut device,
            memory: &Services,
        };
        f(
            &mut self.app,
            &mut self.workspace.classic_with(platform.memory),
            &mut platform,
        )
    }
    fn new() -> Self {
        let mut card = Self {
            app: OpenPgp::new(),
            workspace: SessionWorkspace::new(),
            disk: Disk::default(),
        };
        card.with(|a, _, p| a.install(p)).unwrap();
        card
    }
    fn command(&mut self, ins: u8, p2: u8, input: &[u8]) -> Result<(u32, Sw), Sw> {
        self.with(|a, w, p| {
            let h = Header {
                cla: 0,
                ins,
                p1: 0,
                p2,
            };
            let result = a
                .begin(h, w, p)
                .and_then(|()| a.consume(input, w, p))
                .and_then(|()| a.finish(h, 256, w, p));
            if result.is_err() {
                a.abort(w, p);
            }
            result
        })
    }
    fn verify(&mut self) {
        assert_eq!(self.command(0x20, 0x83, b"12345678"), Ok((0, Sw::SUCCESS)));
    }
    fn aid(&mut self, expected: Result<(u32, Sw), Sw>) {
        assert_eq!(self.command(0xca, 0x4f, &[]), expected);
    }
}

#[test]
fn fixed_state_and_key_discriminators_reject_old_records() {
    use super::repository as repo;
    let mut c = Card::new();
    assert_eq!(c.disk.records[&Record::PgpState.id()].len(), 439);
    assert!(c.with(|_, _, p| repo::meta(p, 0)).is_ok());
    c.disk.records.get_mut(&Record::PgpSig.id()).unwrap()[0] = 1;
    assert!(c.with(|_, _, p| repo::meta(p, 0)).is_err());
    c.disk.records.get_mut(&Record::PgpState.id()).unwrap()[0] = 1;
    assert!(
        c.with(|_, _, p| repo::state(p, &mut [0; repo::STATE_LEN]))
            .is_err()
    );
    let state = c.disk.records.get_mut(&Record::PgpState.id()).unwrap();
    state[0] = 2;
    state[repo::state_layout::NAME] = 40;
    assert!(
        c.with(|_, _, p| repo::state(p, &mut [0; repo::STATE_LEN]))
            .is_err()
    );
}

#[test]
fn install_rejects_old_and_malformed_state_without_reprovisioning() {
    use super::repository as repo;
    let mut c = Card::new();
    let valid = c.disk.records[&Record::PgpState.id()].clone();
    // Version 1 stored four flags, 60 CA-fingerprint bytes, then packed
    // length/value fields: empty name/login/language/URL and sex "9".
    let mut compact = std::vec![0; 64];
    compact[0] = 1;
    compact.extend_from_slice(&[0, 0, 0, 1, b'9', 0]);
    let mut cases = std::vec![compact, valid[..valid.len() - 1].to_vec()];
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);
    for (offset, value) in [
        (repo::state_layout::VERSION, 1),
        (repo::state_layout::TERMINATED, 2),
        (repo::state_layout::PW1_REUSE, 2),
        (repo::state_layout::NAME, 40),
        (repo::state_layout::LOGIN, 64),
        (repo::state_layout::LANGUAGE, 9),
        (repo::state_layout::SEX, 2),
    ] {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        cases.push(malformed);
    }
    for bytes in cases {
        c.disk.records.insert(Record::PgpState.id(), bytes);
        c.app = OpenPgp::new();
        let records = c.disk.records.clone();
        let writes = c.disk.writes;
        assert_eq!(c.with(|a, _, p| a.install(p)), Err(Sw::UNABLE_TO_PROCESS));
        assert_eq!(c.disk.writes, writes, "rejection must not trigger reset");
        assert_eq!(c.disk.records, records, "credentials must remain untouched");
    }
}

#[test]
fn old_key_records_never_reach_private_key_loading() {
    use super::repository as repo;
    let mut c = Card::new();
    let valid = c.disk.records[&Record::PgpSig.id()].clone();
    // An absent version-1 key was just a metadata prefix without a discriminator.
    let mut legacy = valid[1..].to_vec();
    legacy[0] = 1;
    // Even a correctly sized new footer must not authorize an old discriminator.
    let mut disguised = valid.clone();
    disguised[0] = 1;
    for bytes in [legacy, disguised] {
        c.disk.records.insert(Record::PgpSig.id(), bytes);
        let records = c.disk.records.clone();
        let writes = c.disk.writes;
        let mut key = [0xa5; crate::ports::key_layout::SIZE];
        assert!(matches!(
            c.with(|_, _, p| repo::load_key(p, 0, &mut key)),
            Err(super::domain::Error::Storage)
        ));
        assert_eq!(key, [0xa5; crate::ports::key_layout::SIZE]);
        assert_eq!(c.disk.writes, writes);
        assert_eq!(c.disk.records, records);
    }
}

#[test]
fn lifecycle_cache_reloads_uncertain_commits_and_revokes_grants() {
    let active = Ok((16, Sw::SUCCESS));
    let terminated = Err(Sw::SELECTED_FILE_TERMINATED);
    let mut c = Card::new();
    let reads = c.disk.reads;
    c.aid(active);
    assert_eq!(c.disk.reads, reads, "install primes the lifecycle cache");
    c.verify();
    assert_eq!(c.command(0xe6, 0, &[]), Ok((0, Sw::SUCCESS)));
    let reads = c.disk.reads;
    c.aid(terminated);
    assert_eq!(
        c.disk.reads, reads,
        "terminated rejection requires no storage read"
    );
    assert_eq!(c.command(0x44, 0, &[]), Ok((0, Sw::SUCCESS)));
    let reads = c.disk.reads;
    c.aid(active);
    assert_eq!(
        c.disk.reads, reads,
        "successful activation primes the cache"
    );

    for applied in [false, true] {
        c.verify();
        c.disk.fail_write = Some(Record::PgpState);
        c.disk.applied = applied;
        assert_eq!(c.command(0xe6, 0, &[]), Err(Sw::UNABLE_TO_PROCESS));
        c.disk.fail_read = true;
        c.aid(Err(Sw::UNABLE_TO_PROCESS));
        c.disk.fail_read = false;
        let reads = c.disk.reads;
        c.aid(if applied { terminated } else { active });
        assert!(
            c.disk.reads > reads,
            "failed reload cannot validate the cache"
        );
        let reads = c.disk.reads;
        c.aid(if applied { terminated } else { active });
        assert_eq!(c.disk.reads, reads);
        if !applied {
            assert_eq!(
                c.command(0xe6, 0, &[]),
                Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
            );
        }
        assert_eq!(
            c.command(0x44, 0, &[]),
            if applied {
                Ok((0, Sw::SUCCESS))
            } else {
                Err(Sw::CONDITIONS_NOT_SATISFIED)
            }
        );
    }

    // An interrupted reinstall remains terminated until a successful retry.
    c.verify();
    c.command(0xe6, 0, &[]).unwrap();
    c.disk.fail_write = Some(Record::PgpPw1);
    c.disk.applied = false;
    assert_eq!(c.command(0x44, 0, &[]), Err(Sw::UNABLE_TO_PROCESS));
    c.aid(terminated);
    assert_eq!(c.command(0x44, 0, &[]), Ok((0, Sw::SUCCESS)));
    c.aid(active);

    // Metadata shares the lifecycle record; uncertain replacements must also
    // invalidate the cached flag, even though the intended flag stays active.
    for applied in [false, true] {
        c.verify();
        c.disk.fail_write = Some(Record::PgpState);
        c.disk.applied = applied;
        assert_eq!(c.command(0xda, 0x5b, b"Alice"), Err(Sw::UNABLE_TO_PROCESS));
        let reads = c.disk.reads;
        c.aid(active);
        assert!(c.disk.reads > reads);
    }

    // A transport reset invalidates even a previously successful cache entry.
    c.with(|a, w, p| a.reset(w, p));
    c.disk.fail_read = true;
    c.aid(Err(Sw::UNABLE_TO_PROCESS));
    c.disk.fail_read = false;
    c.aid(active);
}
