// SPDX-License-Identifier: Apache-2.0
//! Exercise corrupt/absent records at the command cleanup boundary.
use super::*;
use crate::ports::*;

struct Store {
    bytes: [u8; 1290],
    size: Option<usize>,
    fail_at: Option<u32>,
    material_reads: usize,
}
impl Store {
    fn key(algorithm: u8) -> Self {
        let mut bytes = [0x5a; 1290];
        bytes[..6].copy_from_slice(&[1, algorithm, 2, 2, 0, 0]);
        Self {
            bytes,
            size: Some(6 + repo::material(algorithm)),
            fail_at: None,
            material_reads: 0,
        }
    }
}
impl Storage for Store {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        panic!("unexpected whole-record read")
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        panic!("a failed public-key read must not write storage")
    }
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        assert_eq!(record, Record::PivKey0);
        self.size.map(|n| n as u32).ok_or(StorageError::Missing)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        assert_eq!(record, Record::PivKey0);
        if !out.is_empty() && offset >= 6 {
            self.material_reads += 1;
        }
        if self.fail_at == Some(offset) && !out.is_empty() {
            // A backend may copy a prefix before reporting an I/O failure.
            out[0] = 0x5a;
            return Err(StorageError::Unavailable);
        }
        let end = offset as usize + out.len();
        if end > self.size.ok_or(StorageError::Missing)? {
            return Err(StorageError::Unavailable);
        }
        out.copy_from_slice(&self.bytes[offset as usize..end]);
        Ok(())
    }
}
struct Backend;
impl Crypto for Backend {
    fn key_operation(
        &mut self,
        _: KeyOperation,
        _: u8,
        _: &mut KeyMaterial,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        panic!("invalid/absent key must not reach crypto")
    }
    fn stream(
        &mut self,
        _: StreamOperation,
        _: u8,
        _: &mut CryptoScratch,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        panic!("invalid seed must not reach streaming crypto")
    }
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
impl Device for Backend {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
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
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
fn rejected(store: &mut Store, status: Sw) {
    let mut p = Platform {
        storage: store,
        crypto: &mut Backend,
        device: &mut Backend,
        memory: &Backend,
    };
    let mut piv = Piv::new();
    let mut workspace = SessionWorkspace::new();
    let h = Header {
        cla: 0,
        ins: 0xf7,
        p1: 0,
        p2: 0x9a,
    };
    piv.begin(h, &mut workspace, &mut p).unwrap();
    // Paint after begin: finish must clear even partially overwritten material.
    let w = workspace.classic_with(p.memory);
    w.key.bytes.fill(0xa5);
    w.output.fill(0xa5);
    assert_eq!(piv.finish(h, 256, &mut workspace, &mut p), Err(status));
    let w = workspace.classic_with(p.memory);
    assert!(w.key.bytes.iter().all(|&b| b == 0));
    assert!(w.input.iter().all(|&b| b == 0));
    assert!(w.output.iter().all(|&b| b == 0));
    assert_eq!(piv.body_len, 0);
}

#[test]
fn truncated_seed_and_invalid_key_types_never_reach_crypto() {
    let mut store = Store::key(alg::MLKEM768);
    store.size = Some(6 + 63);
    rejected(&mut store, Sw::UNABLE_TO_PROCESS);
    assert_eq!(store.material_reads, 0);
    for algorithm in [12, 14, 0xff] {
        let mut store = Store::key(alg::P256);
        store.bytes[1] = algorithm;
        rejected(&mut store, Sw::UNABLE_TO_PROCESS);
        assert_eq!(store.material_reads, 0);
    }
}

#[test]
fn absent_keys_and_stale_origin_zero_records_never_load_material() {
    for size in [None, Some(0), Some(6 + 32)] {
        let mut store = Store::key(alg::P256);
        store.bytes[2] = 0;
        store.size = size;
        rejected(
            &mut store,
            if size == Some(38) {
                Sw::UNABLE_TO_PROCESS
            } else {
                Sw::REFERENCE_NOT_FOUND
            },
        );
        assert_eq!(store.material_reads, 0);
    }
}

#[test]
fn partial_scalar_and_each_rsa_component_read_failure_clear_the_workspace() {
    for (algorithm, width) in [(alg::P521, 66), (alg::RSA2048, 128), (alg::RSA4096, 256)] {
        let reads = if repo::rsa(algorithm) { 6 } else { 1 };
        for read in 0..reads {
            let mut store = Store::key(algorithm);
            store.fail_at = Some(if read == 0 {
                6
            } else {
                10 + (read - 1) * width
            });
            rejected(&mut store, Sw::UNABLE_TO_PROCESS);
            assert_eq!(store.material_reads, read as usize + 1);
        }
    }
}
