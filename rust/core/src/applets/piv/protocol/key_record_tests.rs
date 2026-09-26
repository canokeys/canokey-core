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

#[derive(Default)]
struct Streaming {
    initialized: usize,
    finalized: usize,
}
impl Crypto for Streaming {
    fn stream(
        &mut self,
        op: StreamOperation,
        _: u8,
        _: &mut CryptoScratch,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match op {
            StreamOperation::DecapsulateInit => self.initialized += 1,
            StreamOperation::DecapsulateUpdate | StreamOperation::Abort => (),
            StreamOperation::DecapsulateFinal => {
                self.finalized += 1;
                out.fill(0x3c);
                return Ok(32);
            }
            _ => panic!("unexpected crypto operation"),
        }
        Ok(0)
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
struct Gesture {
    samples: usize,
    cancelled: bool,
}
impl Device for Gesture {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        self.samples as u32 * 1000
    }
    fn touched(&mut self) -> bool {
        self.samples += 1;
        self.samples == 2
    }
    fn progress(&mut self) -> bool {
        !self.cancelled
    }
    fn led(&mut self, _: bool) {}
}

#[test]
fn stream_validation_and_pin_precede_touch_and_one_use_grant() {
    let mut store = Store::key(alg::MLKEM768);
    store.bytes[repo::PIN_POLICY] = policy::PIN_ALWAYS;
    store.bytes[repo::TOUCH_POLICY] = policy::TOUCH_ALWAYS;
    let mut crypto = Streaming::default();
    let mut device = Gesture {
        samples: 0,
        cancelled: false,
    };
    let mut piv = Piv::new();
    let mut workspace = SessionWorkspace::new();
    let h = Header {
        cla: 0,
        ins: 0x87,
        p1: 0xe3,
        p2: 0x9a,
    };
    macro_rules! platform {
        () => {
            Platform {
                storage: &mut store,
                crypto: &mut crypto,
                device: &mut device,
                memory: &Backend,
            }
        };
    }
    assert_eq!(
        piv.begin(h, &mut workspace, &mut platform!()),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    assert_eq!((device.samples, crypto.initialized), (0, 0));
    piv.pins.state.pin_ok = true;
    // A complete template missing its ciphertext must not take the gesture.
    piv.begin(h, &mut workspace, &mut platform!()).unwrap();
    piv.consume(&[0x7c, 2, 0x82, 0], &mut workspace, &mut platform!())
        .unwrap();
    assert_eq!(
        piv.finish(h, 256, &mut workspace, &mut platform!()),
        Err(Sw::WRONG_DATA)
    );
    piv.close(&mut workspace, &mut platform!());
    assert_eq!(device.samples, 0);
    assert!(!piv.pin_grant_consumed);

    let mut command = [0; 1098];
    command[..10].copy_from_slice(&[0x7c, 0x82, 0x04, 0x46, 0x82, 0, 0x81, 0x82, 0x04, 0x40]);
    piv.begin(h, &mut workspace, &mut platform!()).unwrap();
    piv.consume(
        &command[..command.len() - 1],
        &mut workspace,
        &mut platform!(),
    )
    .unwrap();
    assert_eq!(
        piv.finish(h, 256, &mut workspace, &mut platform!()),
        Err(Sw::WRONG_LENGTH)
    );
    piv.close(&mut workspace, &mut platform!());
    assert_eq!((device.samples, crypto.finalized), (0, 0));
    assert!(!piv.pin_grant_consumed);

    for cancelled in [true, false] {
        device.cancelled = cancelled;
        device.samples = 0;
        piv.begin(h, &mut workspace, &mut platform!()).unwrap();
        for chunk in command.chunks(193) {
            piv.consume(chunk, &mut workspace, &mut platform!())
                .unwrap();
        }
        assert_eq!(device.samples, 0);
        let result = piv.finish(h, 256, &mut workspace, &mut platform!());
        if cancelled {
            assert_eq!(result, Err(Sw::EXECUTION_ERROR));
            assert!(!piv.pin_grant_consumed);
            assert_eq!(crypto.finalized, 0);
        } else {
            assert_eq!(result, Ok((36, Sw::SUCCESS)));
            assert!(piv.pin_grant_consumed);
            assert_eq!((device.samples, crypto.finalized), (3, 1));
        }
        piv.close(&mut workspace, &mut platform!());
    }
    let initialized = crypto.initialized;
    assert_eq!(
        piv.begin(h, &mut workspace, &mut platform!()),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    assert_eq!((device.samples, crypto.initialized), (3, initialized));
}

#[test]
fn classic_unauthorized_signature_does_not_consume_touch() {
    let mut store = Store::key(alg::P256);
    store.bytes[repo::TOUCH_POLICY] = policy::TOUCH_ALWAYS;
    let mut crypto = Streaming::default();
    let mut device = Gesture {
        samples: 0,
        cancelled: false,
    };
    let mut piv = Piv::new();
    let mut workspace = SessionWorkspace::new();
    let h = Header {
        cla: 0,
        ins: 0x87,
        p1: 0x11,
        p2: 0x9a,
    };
    let mut p = Platform {
        storage: &mut store,
        crypto: &mut crypto,
        device: &mut device,
        memory: &Backend,
    };
    piv.begin(h, &mut workspace, &mut p).unwrap();
    let mut command = [0; 38];
    command[..6].copy_from_slice(&[0x7c, 36, 0x82, 0, 0x81, 32]);
    piv.consume(&command, &mut workspace, &mut p).unwrap();
    assert_eq!(
        piv.finish(h, 256, &mut workspace, &mut p),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    assert_eq!(device.samples, 0);
}
