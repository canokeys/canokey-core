// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::ports::*;
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    vec,
    vec::Vec,
};

#[derive(Default)]
struct Backend {
    signed: Vec<u8>,
    hashed: Vec<u8>,
    offset: usize,
    aborts: usize,
    opens: usize,
    fail: Option<Op>,
    short: bool,
    cancel: bool,
    key_result: Option<Result<usize, StorageError>>,
    fail_attestation: bool,
    wiped_attestation: Cell<bool>,
    wiped: RefCell<Vec<(usize, usize)>>,
}
impl Storage for Backend {
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        unreachable!()
    }
    fn load(&mut self, record: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        assert_eq!(record, Record::CtapAttestationKey);
        out.fill(0x19);
        self.key_result.unwrap_or(Ok(32))
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        assert_eq!(record, Record::CtapCertificate);
        out.copy_from_slice(&b"certificate"[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
}
impl Crypto for Backend {
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn stream(
        &mut self,
        op: Op,
        algorithm: u8,
        scratch: &mut CryptoScratch,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert_eq!(algorithm, alg::MLDSA65);
        if self.fail.is_some_and(|fail| fail as u8 == op as u8) {
            // Model a primitive that has written sensitive state before failing.
            scratch.bytes.fill(0xc7);
            return Err(CryptoError::Failure);
        }
        Ok(match op {
            Op::SignInit | Op::PublicInit => {
                assert_eq!(input, [0x5a; 32]);
                assert!(scratch.bytes.iter().all(|&b| b == 0));
                scratch.bytes.fill(0xc7);
                self.offset = 0;
                self.opens += 1;
                PUBLIC_BYTES
            }
            Op::SignUpdate => {
                self.signed.extend_from_slice(input);
                0
            }
            Op::SignFinal => SIGNATURE_BYTES,
            Op::Read => {
                for (i, b) in out.iter_mut().enumerate() {
                    *b = ((self.offset + i) % 251) as u8;
                }
                self.offset += out.len();
                out.len() - usize::from(self.short)
            }
            Op::Abort => {
                self.aborts += 1;
                scratch.bytes.fill(0);
                0
            }
            _ => unreachable!(),
        })
    }
    fn digest(
        &mut self,
        op: Hash,
        _: &mut HashState,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        match op {
            Hash::Init => self.hashed.clear(),
            Hash::Update => self.hashed.extend_from_slice(input),
            Hash::Final => out.copy_from_slice(&Sha256::digest(&self.hashed)),
            Hash::Abort => {}
        }
        Ok(())
    }
    fn p256_sign(
        &mut self,
        key: &[u8; 32],
        digest: &[u8; 32],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        assert_eq!(key, &[0x19; 32]);
        assert_eq!(&Sha256::digest(&self.hashed)[..], digest);
        out.fill(1);
        if self.fail_attestation {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn sha256(&mut self, _: &[u8], _: &mut [u8; 32]) -> Result<(), CryptoError> {
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
    fn progress(&mut self) -> bool {
        !self.cancel
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn led(&mut self, _: bool) {}
}
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        if bytes == [0x19; 32] {
            self.wiped_attestation.set(true);
        }
        self.wiped
            .borrow_mut()
            .push((bytes.as_ptr() as usize, bytes.len()));
        bytes.fill(0);
    }
}
fn platform<'a>(
    storage: &'a mut Backend,
    crypto: &'a mut Backend,
    device: &'a mut Backend,
    memory: &'a Backend,
) -> Platform<'a> {
    Platform {
        storage,
        crypto,
        device,
        memory,
    }
}
fn plan(mode: Mode) -> Pending {
    Pending {
        mode,
        prefix: 4,
        auth: if matches!(mode, Mode::Assert) { 37 } else { 0 },
        public_at: 8,
        signature_at: 12,
        certificate: matches!(mode, Mode::Make).then_some((16, 11)),
        output: 20,
        hash_prefix: (4, 4),
        hash_suffix: (8, 4),
    }
}
fn staged(plan: Pending, memory: &Backend) -> SessionWorkspace {
    let mut w = SessionWorkspace::new();
    let classic = w.classic_with(memory);
    classic.key.bytes.fill(0xa5);
    classic.input.fill(0xa6);
    classic.output.fill(0xa7);
    for (i, b) in classic.output[..plan.output].iter_mut().enumerate() {
        *b = i as u8;
    }
    classic.input[plan.auth..plan.auth + 32].fill(0x33);
    classic.input[plan.auth + 32..plan.auth + 64].fill(0x5a);
    w
}
fn erased(stream: &Stream<'_>) {
    assert!(stream.crypto.bytes.iter().all(|&b| b == 0));
    assert!(stream.framing.bytes.iter().all(|&b| b == 0));
    assert_eq!(stream.framing.material, [0; 64]);
}

#[test]
fn framing_stays_in_place_and_every_segment_boundary_reads_exactly() {
    for mode in [Mode::Assert, Mode::Public, Mode::Make] {
        for chunk in [1, 4, 11, 64, 255, 1024, 4096] {
            let plan = plan(mode);
            let mut storage = Backend::default();
            let mut crypto = Backend::default();
            let mut device = Backend::default();
            let memory = Backend::default();
            let mut w = staged(plan, &memory);
            let old = w.classic_with(&memory);
            let (output_at, key_at, input_at) = (
                old.output.as_ptr() as usize,
                old.key.bytes.as_ptr() as usize,
                old.input.as_ptr() as usize,
            );
            let mut p = platform(&mut storage, &mut crypto, &mut device, &memory);
            let length = Stream::prepare(plan, &mut w, &mut p).unwrap();
            let mut stream = w.ctap_stream().unwrap();
            assert_eq!(stream.framing.bytes.as_ptr() as usize, output_at);
            assert_eq!(stream.framing.material, [0; 64]);
            assert!(
                stream.framing.bytes[stream.framing.length..]
                    .iter()
                    .all(|&b| b == 0)
            );
            assert!(memory.wiped.borrow().contains(&(key_at, key_layout::SIZE)));
            assert!(
                memory
                    .wiped
                    .borrow()
                    .contains(&(input_at, crate::runtime::workspace::INPUT_BYTES))
            );
            let mut expected: Vec<u8> = (0..20).collect();
            if matches!(mode, Mode::Assert) {
                expected.splice(4..4, vec![0xa6; 37]);
            }
            if matches!(mode, Mode::Make) {
                // DER sequence of two positive, 32-byte integers, wrapped in CBOR.
                let signature: Vec<u8> = [
                    vec![0x58, 70, 0x30, 68, 2, 32],
                    vec![1; 32],
                    vec![2, 32],
                    vec![1; 32],
                ]
                .concat();
                expected.splice(12..12, signature);
                expected.splice(16 + 72..16 + 72, b"certificate".iter().copied());
            }
            let generated_at = if matches!(mode, Mode::Assert) { 49 } else { 8 };
            let generated_len = if matches!(mode, Mode::Assert) {
                SIGNATURE_BYTES
            } else {
                PUBLIC_BYTES
            };
            expected.splice(
                generated_at..generated_at,
                (0..generated_len).map(|i| (i % 251) as u8),
            );
            assert_eq!(length, expected.len());
            let mut actual = vec![0; length];
            for (index, out) in actual.chunks_mut(chunk).enumerate() {
                stream.read(index * chunk, out, &mut p).unwrap();
            }
            assert_eq!(actual, expected);
            assert_eq!(stream.read(0, &mut [0], &mut p), Err(Sw::WRONG_LENGTH));
            assert_eq!(stream.read(length, &mut [0], &mut p), Err(Sw::WRONG_LENGTH));
            stream.close(&mut p);
            erased(&stream);
            if matches!(mode, Mode::Assert) {
                assert_eq!(crypto.signed, [vec![0xa6; 37], vec![0x33; 32]].concat());
            }
            if matches!(mode, Mode::Make) {
                assert_eq!(
                    crypto.hashed,
                    [
                        (4..8).collect::<Vec<u8>>(),
                        (0..PUBLIC_BYTES).map(|i| (i % 251) as u8).collect(),
                        (8..12).collect(),
                        vec![0x33; 32]
                    ]
                    .concat()
                );
            }
            assert_eq!(
                crypto.aborts,
                if matches!(mode, Mode::Make) { 2 } else { 1 }
            );
            let old = w.classic_with(&memory);
            assert!(
                old.input
                    .iter()
                    .chain(old.output.iter())
                    .chain(old.key.bytes.iter())
                    .all(|&b| b == 0)
            );
        }
    }
}

#[test]
fn failed_initialization_and_cancelled_generation_erase_retained_material() {
    for (mode, fail, cancel) in [
        (Mode::Assert, Some(Op::SignInit), false),
        (Mode::Assert, Some(Op::SignUpdate), false),
        (Mode::Assert, Some(Op::SignFinal), false),
        (Mode::Public, Some(Op::PublicInit), false),
        (Mode::Make, Some(Op::Read), false),
        (Mode::Make, None, true),
    ] {
        let mut storage = Backend::default();
        let mut crypto = Backend {
            fail,
            ..Backend::default()
        };
        let mut device = Backend {
            cancel,
            ..Backend::default()
        };
        let memory = Backend::default();
        let mut w = staged(plan(mode), &memory);
        let mut p = platform(&mut storage, &mut crypto, &mut device, &memory);
        assert_eq!(
            Stream::prepare(plan(mode), &mut w, &mut p),
            Err(if cancel {
                Status::Cancelled
            } else {
                Status::Other
            })
        );
        erased(&w.ctap_stream().unwrap());
        assert!(crypto.aborts > 0);
    }
}

#[test]
fn short_or_failed_generated_read_does_not_advance_response() {
    for short in [true, false] {
        let mut storage = Backend::default();
        let mut crypto = Backend::default();
        let mut device = Backend::default();
        let memory = Backend::default();
        let mut w = staged(plan(Mode::Public), &memory);
        Stream::prepare(
            plan(Mode::Public),
            &mut w,
            &mut platform(&mut storage, &mut crypto, &mut device, &memory),
        )
        .unwrap();
        crypto.short = short;
        crypto.fail = (!short).then_some(Op::Read);
        let mut p = platform(&mut storage, &mut crypto, &mut device, &memory);
        let mut stream = w.ctap_stream().unwrap();
        assert_eq!(
            stream.read(0, &mut [0; 64], &mut p),
            Err(Sw::UNABLE_TO_PROCESS)
        );
        assert_eq!(stream.framing.emitted, 0);
        stream.close(&mut p);
        erased(&stream);
    }
}

#[test]
fn full_capacity_insertion_preserves_both_sides_and_overflow_is_non_mutating() {
    let mut plan = plan(Mode::Assert);
    plan.output = crate::runtime::workspace::OUTPUT_BYTES;
    plan.auth = FRAMING_BYTES - plan.output;
    let mut storage = Backend::default();
    let mut crypto = Backend::default();
    let mut device = Backend::default();
    let memory = Backend::default();
    let mut w = staged(plan, &memory);
    let original = w.classic_with(&memory).output.to_vec();
    let mut p = platform(&mut storage, &mut crypto, &mut device, &memory);
    let mut oversized = plan;
    oversized.auth += 1;
    assert_eq!(
        Stream::transfer(oversized, &mut w, &mut p),
        Err(Status::Other)
    );
    assert!(w.ctap_stream().is_none());
    assert_eq!(w.classic_with(&memory).output.as_slice(), original);
    Stream::transfer(plan, &mut w, &mut p).unwrap();
    let stream = w.ctap_stream().unwrap();
    assert_eq!(stream.framing.length, FRAMING_BYTES);
    assert_eq!(
        &stream.framing.bytes[..plan.prefix],
        &original[..plan.prefix]
    );
    assert_eq!(
        &stream.framing.bytes[plan.prefix..plan.prefix + plan.auth],
        vec![0xa6; plan.auth]
    );
    assert_eq!(
        &stream.framing.bytes[plan.prefix + plan.auth..],
        &original[plan.prefix..]
    );
}

#[test]
fn failed_attestation_erases_partial_key_and_closes_stream() {
    for key_result in [
        Ok(0),
        Ok(31),
        Err(StorageError::Missing),
        Err(StorageError::Unavailable),
        Err(StorageError::Uncertain),
        Ok(32),
    ] {
        let mut storage = Backend {
            key_result: Some(key_result),
            ..Backend::default()
        };
        let mut crypto = Backend {
            fail_attestation: true,
            ..Backend::default()
        };
        let mut device = Backend::default();
        let memory = Backend::default();
        let mut w = staged(plan(Mode::Make), &memory);
        let mut p = platform(&mut storage, &mut crypto, &mut device, &memory);
        assert_eq!(
            Stream::prepare(plan(Mode::Make), &mut w, &mut p),
            Err(Status::Other)
        );
        erased(&w.ctap_stream().unwrap());
        assert!(memory.wiped_attestation.get());
        assert!(crypto.aborts > 0);
    }
}
