// SPDX-License-Identifier: Apache-2.0
extern crate std;
use crate::{applets::openpgp::protocol::OpenPgp, ports::*, runtime::workspace::Workspace};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Default)]
struct Disk {
    records: BTreeMap<u8, Vec<u8>>,
    staged: Vec<u8>,
    reads: usize,
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
    workspace: Workspace,
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
        f(&mut self.app, &mut self.workspace, &mut platform)
    }
    fn new() -> Self {
        let mut card = Self {
            app: OpenPgp::new(),
            workspace: Workspace::new(),
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
        assert_eq!(c.command(0x44, 0, &[]), Ok((0, Sw::SUCCESS)));
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
