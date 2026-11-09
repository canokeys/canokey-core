// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "streaming")]
use canokey_ctap::streaming::{FRAMING_BYTES, Framing, Mode, Pending, Profile, Stream};
use canokey_ports::{
    BackendTypes, Crypto, CryptoError, CryptoScratch, Device, DigestOperation as Hash, HashState,
    Memory, Platform, Record, Storage, StorageError, StreamOperation as Op, mldsa,
};
use canokey_protocol::response::StatusWord as Sw;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Hash(u8),
    Key,
    Sign,
    Certificate,
    Reopen,
    Cancel,
    Short,
    PublicLength,
    SignatureLength,
}
#[derive(Debug, PartialEq, Eq)]
enum Error {
    Invalid,
    Cancelled,
    Material,
}
#[derive(Default)]
struct Fixture {
    events: Rc<RefCell<Vec<&'static str>>>,
    fault: Option<Fault>,
    opens: usize,
    offset: usize,
    transcript: Vec<u8>,
}
impl Storage for Fixture {
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        unreachable!()
    }
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        unreachable!()
    }
}
impl Crypto for Fixture {
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
    fn stream(
        &mut self,
        op: Op,
        algorithm: u8,
        scratch: &mut CryptoScratch,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let params = mldsa::parameters(algorithm).unwrap();
        Ok(match op {
            Op::PublicInit | Op::SignInit => {
                self.events.borrow_mut().push("open");
                self.opens += 1;
                assert_eq!(input, [0x5a; mldsa::SEED_BYTES]);
                assert!(scratch.bytes.iter().all(|&byte| byte == 0x00));
                scratch.bytes.fill(0xc7);
                self.offset = 0;
                if self.fault == Some(Fault::Reopen) && self.opens == 2 {
                    return Err(CryptoError::Failure);
                }
                params.public_bytes - usize::from(self.fault == Some(Fault::PublicLength))
            }
            Op::SignUpdate => {
                self.transcript.extend_from_slice(input);
                0
            }
            Op::SignFinal => {
                params.signature_bytes - usize::from(self.fault == Some(Fault::SignatureLength))
            }
            Op::Read => {
                self.events.borrow_mut().push("read");
                for (index, byte) in output.iter_mut().enumerate() {
                    *byte = ((self.offset + index) % 251) as u8;
                }
                self.offset += output.len();
                output.len() - usize::from(self.fault == Some(Fault::Short))
            }
            Op::Abort => {
                self.events.borrow_mut().push("stream-abort");
                scratch.bytes.fill(0x00);
                0
            }
            _ => unreachable!(),
        })
    }
    fn digest(
        &mut self,
        op: Hash,
        state: &mut HashState,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.events.borrow_mut().push(match op {
            Hash::Init => "hash-init",
            Hash::Update => "hash-update",
            Hash::Final => "hash-final",
            Hash::Abort => "hash-abort",
        });
        if self.fault == Some(Fault::Hash(op as u8)) {
            state.bytes.fill(0xc7);
            return Err(CryptoError::Failure);
        }
        match op {
            Hash::Init => self.transcript.clear(),
            Hash::Update => self.transcript.extend_from_slice(input),
            // Core's integration fixture independently checks actual SHA-256.
            // This fixture isolates transcript and primitive-lifetime ordering.
            Hash::Final => output.fill(0xd1),
            Hash::Abort => state.bytes.fill(0x00),
        }
        Ok(())
    }
    fn p256_sign(
        &mut self,
        key: &[u8; 32],
        digest: &[u8; 32],
        output: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        self.events.borrow_mut().push("sign");
        assert_eq!(key, &[0x19; 32]);
        assert_eq!(digest, &[0xd1; 32]);
        output.fill(0x01);
        if self.fault == Some(Fault::Sign) {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
}
impl Device for Fixture {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn led(&mut self, _: bool) {}
    fn progress(&mut self) -> bool {
        self.fault != Some(Fault::Cancel)
    }
}
impl Memory for Fixture {
    fn wipe(&self, bytes: &mut [u8]) {
        self.events.borrow_mut().push(if bytes == [0x19; 32] {
            "wipe-key"
        } else {
            "wipe"
        });
        bytes.fill(0x00);
    }
}
type Family = BackendTypes<Fixture, Fixture, Fixture, Fixture>;
struct Material;
impl Profile<Family> for Material {
    type Error = Error;
    fn invalid() -> Error {
        Error::Invalid
    }
    fn cancelled() -> Error {
        Error::Cancelled
    }
    fn key(output: &mut [u8; 32], platform: &mut Platform<'_, Family>) -> Result<(), Error> {
        platform.storage.events.borrow_mut().push("key");
        output.fill(0x19);
        if platform.storage.fault == Some(Fault::Key) {
            Err(Error::Material)
        } else {
            Ok(())
        }
    }
    fn certificate(
        offset: u32,
        output: &mut [u8],
        platform: &mut Platform<'_, Family>,
    ) -> Result<(), Sw> {
        platform.storage.events.borrow_mut().push("certificate");
        if platform.storage.fault == Some(Fault::Certificate) {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = 0xe0 + (offset as usize + index) as u8;
        }
        Ok(())
    }
}
struct Harness {
    storage: Fixture,
    crypto: Fixture,
    device: Fixture,
    memory: Fixture,
}
impl Harness {
    fn new(fault: Option<Fault>) -> Self {
        let events = Rc::default();
        let fixture = || Fixture {
            events: Rc::clone(&events),
            fault,
            ..Fixture::default()
        };
        Self {
            storage: fixture(),
            crypto: fixture(),
            device: fixture(),
            memory: fixture(),
        }
    }
    fn platform(&mut self) -> Platform<'_, Family> {
        Platform::new(
            &mut self.storage,
            &mut self.crypto,
            &mut self.device,
            &self.memory,
        )
    }
}
fn plan(algorithm: u8, mode: Mode) -> Pending {
    Pending {
        algorithm,
        mode,
        prefix: 4,
        auth: if matches!(mode, Mode::Assert) { 37 } else { 0 },
        public_at: 8,
        signature_at: 12,
        certificate: Some((16, 11)),
        output: 20,
        hash_prefix: (4, 4),
        hash_suffix: (8, 4),
    }
}
fn stage(framing: &mut Framing, plan: Pending, memory: &Fixture) {
    framing.bytes.fill(0xa7);
    for (index, byte) in framing.bytes[..plan.output].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut input = vec![0xa6; plan.auth];
    input.extend_from_slice(&[0x33; 32]);
    input.extend_from_slice(&[0x5a; mldsa::SEED_BYTES]);
    let params = framing.stage(plan, &input, memory).unwrap();
    framing.activate(plan, params);
}
fn erased(stream: &Stream<'_>) {
    assert!(stream.crypto.bytes.iter().all(|&byte| byte == 0x00));
    assert!(stream.framing.bytes.iter().all(|&byte| byte == 0x00));
    assert_eq!(stream.framing.material(), &[0x00; 64]);
    assert_eq!(stream.len(), 0);
    assert_eq!(stream.framing.emitted(), 0);
}
#[test]
fn public_stream_and_certificate_use_all_five_segments_without_product_code() {
    for params in mldsa::PARAMETER_SETS {
        for chunk in [1, 7, 128, 4096] {
            let request = plan(params.algorithm, Mode::Public);
            let mut harness = Harness::new(None);
            let mut framing = Framing::new();
            stage(&mut framing, request, &harness.memory);
            let mut scratch = CryptoScratch::new();
            let mut stream = Stream {
                crypto: &mut scratch,
                framing: &mut framing,
            };
            let length = stream
                .prepare::<Material, _>(request, &mut harness.platform())
                .unwrap();
            let expected: Vec<u8> = (0x00..0x08)
                .chain((0..params.public_bytes).map(|index| (index % 251) as u8))
                .chain(0x08..0x10)
                .chain(0xe0..0xeb)
                .chain(0x10..0x14)
                .collect();
            assert_eq!(length, expected.len());
            assert_eq!(stream.framing.material(), &[0x00; 64]);
            let mut actual = vec![0x00; length];
            for (index, output) in actual.chunks_mut(chunk).enumerate() {
                stream
                    .read::<Material, _>(index * chunk, output, &mut harness.platform())
                    .unwrap();
            }
            assert_eq!(actual, expected);
            stream.close(&mut harness.platform());
            erased(&stream);
        }
    }
}
#[test]
fn make_closes_public_generation_before_attestation_then_reopens_the_same_seed() {
    for params in mldsa::PARAMETER_SETS {
        let request = plan(params.algorithm, Mode::Make);
        let mut harness = Harness::new(None);
        let mut framing = Framing::new();
        stage(&mut framing, request, &harness.memory);
        let mut scratch = CryptoScratch::new();
        let mut stream = Stream {
            crypto: &mut scratch,
            framing: &mut framing,
        };
        stream
            .prepare::<Material, _>(request, &mut harness.platform())
            .unwrap();
        let expected: Vec<u8> = (0x04..0x08)
            .chain((0..params.public_bytes).map(|index| (index % 251) as u8))
            .chain(0x08..0x0c)
            .chain([0x33; 32])
            .collect();
        assert_eq!(harness.crypto.transcript, expected);
        let events = harness.crypto.events.borrow().clone();
        let relevant: Vec<_> = events
            .into_iter()
            .filter(|event| {
                [
                    "open",
                    "hash-final",
                    "hash-abort",
                    "stream-abort",
                    "key",
                    "sign",
                    "wipe-key",
                ]
                .contains(event)
            })
            .collect();
        assert_eq!(
            relevant,
            [
                "open",
                "hash-final",
                "hash-abort",
                "stream-abort",
                "key",
                "sign",
                "wipe-key",
                "open"
            ]
        );
        assert_eq!(stream.framing.material(), &[0x00; 64]);
        stream.close(&mut harness.platform());
        erased(&stream);
    }
}
#[test]
fn every_hash_failure_aborts_both_primitives_before_erasing_the_session() {
    for params in mldsa::PARAMETER_SETS {
        for op in [Hash::Init, Hash::Update, Hash::Final] {
            let request = plan(params.algorithm, Mode::Make);
            let mut harness = Harness::new(Some(Fault::Hash(op as u8)));
            let mut framing = Framing::new();
            stage(&mut framing, request, &harness.memory);
            let mut scratch = CryptoScratch::new();
            let mut stream = Stream {
                crypto: &mut scratch,
                framing: &mut framing,
            };
            assert_eq!(
                stream.prepare::<Material, _>(request, &mut harness.platform()),
                Err(Error::Invalid)
            );
            erased(&stream);
            let events = harness.crypto.events.borrow();
            let hash_abort = events
                .iter()
                .position(|event| *event == "hash-abort")
                .unwrap();
            let stream_abort = events
                .iter()
                .position(|event| *event == "stream-abort")
                .unwrap();
            assert!(hash_abort < stream_abort);
            assert!(!events.contains(&"key") && !events.contains(&"sign"));
        }
    }
}
#[test]
fn material_sign_cancel_reopen_and_primitive_length_failures_erase_all_backing() {
    for params in mldsa::PARAMETER_SETS {
        for (mode, fault, expected) in [
            (Mode::Make, Fault::Key, Error::Material),
            (Mode::Make, Fault::Sign, Error::Invalid),
            (Mode::Make, Fault::Cancel, Error::Cancelled),
            (Mode::Make, Fault::Reopen, Error::Invalid),
            (Mode::Make, Fault::Short, Error::Invalid),
            (Mode::Public, Fault::PublicLength, Error::Invalid),
            (Mode::Assert, Fault::SignatureLength, Error::Invalid),
        ] {
            let request = plan(params.algorithm, mode);
            let mut harness = Harness::new(Some(fault));
            let mut framing = Framing::new();
            stage(&mut framing, request, &harness.memory);
            let mut scratch = CryptoScratch::new();
            let mut stream = Stream {
                crypto: &mut scratch,
                framing: &mut framing,
            };
            assert_eq!(
                stream.prepare::<Material, _>(request, &mut harness.platform()),
                Err(expected)
            );
            erased(&stream);
            let events = harness.crypto.events.borrow();
            if matches!(fault, Fault::Key | Fault::Sign | Fault::Reopen) {
                assert!(events.contains(&"wipe-key"));
            }
            if fault == Fault::Cancel {
                assert!(!events.contains(&"read") && !events.contains(&"key"));
            }
        }
    }
}
#[test]
fn certificate_failure_does_not_publish_a_partial_response_cursor() {
    for params in mldsa::PARAMETER_SETS {
        let request = plan(params.algorithm, Mode::Public);
        let mut harness = Harness::new(Some(Fault::Certificate));
        let mut framing = Framing::new();
        stage(&mut framing, request, &harness.memory);
        let mut scratch = CryptoScratch::new();
        let mut stream = Stream {
            crypto: &mut scratch,
            framing: &mut framing,
        };
        let length = stream
            .prepare::<Material, _>(request, &mut harness.platform())
            .unwrap();
        let mut output = vec![0x00; length];
        assert_eq!(
            stream.read::<Material, _>(1, &mut output[..1], &mut harness.platform()),
            Err(Sw::WRONG_LENGTH)
        );
        assert!(!harness.crypto.events.borrow().contains(&"read"));
        assert_eq!(
            stream.read::<Material, _>(0, &mut output, &mut harness.platform()),
            Err(Sw::UNABLE_TO_PROCESS)
        );
        assert_eq!(stream.framing.emitted(), 0);
        // A failed primitive read is terminal for the outer response owner;
        // it closes the stream instead of retrying a consumed native stream.
        stream.close(&mut harness.platform());
        erased(&stream);
    }
}
#[test]
fn attestation_insertion_at_capacity_fails_after_wiping_the_temporary_key() {
    let mut request = plan(mldsa::DSA65.algorithm, Mode::Make);
    request.output = FRAMING_BYTES;
    let mut harness = Harness::new(None);
    let mut framing = Framing::new();
    stage(&mut framing, request, &harness.memory);
    let mut scratch = CryptoScratch::new();
    let mut stream = Stream {
        crypto: &mut scratch,
        framing: &mut framing,
    };
    assert_eq!(
        stream.prepare::<Material, _>(request, &mut harness.platform()),
        Err(Error::Invalid)
    );
    erased(&stream);
    assert!(harness.crypto.events.borrow().contains(&"wipe-key"));
    assert_eq!(harness.crypto.opens, 1);
}
