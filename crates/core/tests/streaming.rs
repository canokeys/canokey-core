// SPDX-License-Identifier: Apache-2.0
//! Normal long-input scenarios through the production Runtime. This router is
//! host-only; it exercises consumer contracts, not a shipped PIV implementation.
use canokey_protocol::{apdu::Header, response::StatusWord as Sw, tlv};
use canokey_rust_core::{
    ports::*,
    runtime::engine::{Router, Runtime},
};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct StorageBackend {
    staged: Vec<u8>,
    object: Vec<u8>,
    commits: usize,
}
impl Storage for StorageBackend {
    fn load(&mut self, record: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        if matches!(record, Record::CtapPin) {
            return Err(StorageError::Missing);
        }
        out[..self.object.len()].copy_from_slice(&self.object);
        Ok(self.object.len())
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        self.object = core::mem::take(&mut self.staged);
        self.commits += 1;
        Ok(())
    }
    fn replace_at(&mut self, _: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        assert_eq!(offset as usize, self.staged.len());
        self.staged.extend_from_slice(input);
        Ok(())
    }
    fn read_at(&mut self, _: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        out.copy_from_slice(&self.object[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
}
struct CryptoBackend;
impl Crypto for CryptoBackend {
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
struct DeviceBackend;
impl Device for DeviceBackend {
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
struct MemoryBackend;
impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

// Only the non-streamable key components consume significant consumer RAM.
// Neither object payload nor signed message is retained in the runtime.
// Deliberate fixed shared workspace: boxing would conceal the memory budget.
#[allow(clippy::large_enum_variant)]
enum Sink {
    None,
    Key {
        components: [[u8; 256]; 5],
        field: usize,
        offset: usize,
    },
    Hash(Sha256),
    Object(u32),
}
#[derive(Clone, Copy)]
enum Failure {
    EndFrame,
    Finish,
    Read,
}
struct Fixture {
    failure: Option<Failure>,
    events: Vec<&'static str>,
    sink: Sink,
    tlv: tlv::Decoder,
    selected: bool,
    frames: usize,
    finishes: usize,
    closes: usize,
    reads: usize,
    generated: usize,
    finished_header: Option<Header>,
    last_frame: bool,
    next: u32,
    total: u32,
    digest: [u8; 32],
    key_digest: [u8; 32],
    response_open: bool,
}
impl Fixture {
    fn new() -> Self {
        Self {
            failure: None,
            events: Vec::new(),
            sink: Sink::None,
            tlv: tlv::Decoder::default(),
            selected: false,
            frames: 0,
            finishes: 0,
            closes: 0,
            reads: 0,
            generated: 0,
            finished_header: None,
            last_frame: false,
            next: 0,
            total: 0,
            digest: [0; 32],
            key_digest: [0; 32],
            response_open: false,
        }
    }
}
impl Router for Fixture {
    fn install(&mut self, _: &mut Platform<'_, impl canokey_ports::Backends>) -> Result<(), Sw> {
        Ok(())
    }
    fn reset(&mut self, _: &mut Platform<'_, impl canokey_ports::Backends>) {
        self.selected = false;
    }
    fn selected(&self) -> bool {
        self.selected
    }
    fn select(
        &mut self,
        aid: &[u8],
        _: canokey_protocol::apdu::Transport,
        _: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<u32, Sw> {
        assert_eq!(aid, [1]);
        self.selected = true;
        Ok(0)
    }
    fn command_limit(&self, _: Header) -> Result<u32, Sw> {
        Ok(100_000)
    }
    fn abort_command(&mut self, _: &mut Platform<'_, impl canokey_ports::Backends>) {
        self.events.push("abort");
        self.sink = Sink::None;
        self.tlv = tlv::Decoder::default();
    }
    fn begin_command(
        &mut self,
        h: Header,
        _: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<(), Sw> {
        self.sink = match h.ins {
            0x01 => Sink::Key {
                components: [[0; 256]; 5],
                field: 0,
                offset: 0,
            },
            0x02 => Sink::Hash(Sha256::new()),
            0x03 => Sink::Object(0),
            0x04 => Sink::None,
            _ => unreachable!(),
        };
        Ok(())
    }
    fn consume(
        &mut self,
        bytes: &[u8],
        p: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<(), Sw> {
        match &mut self.sink {
            Sink::Key {
                components,
                field,
                offset,
            } => self
                .tlv
                .feed(bytes, &mut |event| {
                    match event {
                        tlv::Event::Start { tag, length } => {
                            assert_eq!(tag.bytes(), [*field as u8 + 1]);
                            assert_eq!(length, 256);
                            *offset = 0;
                        }
                        tlv::Event::Value(bytes) => {
                            components[*field][*offset..*offset + bytes.len()]
                                .copy_from_slice(bytes);
                            *offset += bytes.len();
                        }
                        tlv::Event::End => {
                            assert_eq!(*offset, 256);
                            *field += 1;
                        }
                    };
                    Ok(())
                })
                .map_err(|_| Sw::WRONG_DATA)?,
            Sink::Hash(hash) => hash.update(bytes),
            Sink::Object(offset) => {
                p.storage.replace_at(Record::Pass, *offset, bytes).unwrap();
                *offset += bytes.len() as u32;
            }
            Sink::None => assert!(bytes.is_empty()),
        };
        Ok(())
    }
    fn end_frame(
        &mut self,
        last: bool,
        _: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<(), Sw> {
        self.events.push("end");
        if matches!(self.failure, Some(Failure::EndFrame)) {
            return Err(Sw::WRONG_DATA);
        }
        self.frames += 1;
        self.last_frame = last;
        Ok(())
    }
    fn finish(
        &mut self,
        h: Header,
        _: u32,
        p: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<(u32, Sw), Sw> {
        self.events.push("finish");
        if matches!(self.failure, Some(Failure::Finish)) {
            return Err(Sw::WRONG_P1P2);
        }
        self.finishes += 1;
        self.finished_header = Some(h);
        self.total = match core::mem::replace(&mut self.sink, Sink::None) {
            Sink::Key {
                components, field, ..
            } => {
                core::mem::take(&mut self.tlv).finish().unwrap();
                assert_eq!(field, 5);
                let mut hash = Sha256::new();
                for component in components {
                    hash.update(component);
                }
                self.key_digest = hash.finalize().into();
                0
            }
            Sink::Hash(hash) => {
                self.digest = hash.finalize().into();
                32
            }
            Sink::Object(offset) => {
                p.storage.replace(Record::Pass, &[]).unwrap();
                offset
            }
            Sink::None => {
                assert_eq!(h.ins, 0x04);
                self.generated += 1;
                4096
            }
        };
        self.next = 0;
        self.response_open = self.total != 0;
        Ok((self.total, Sw::SUCCESS))
    }
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        p: &mut Platform<'_, impl canokey_ports::Backends>,
    ) -> Result<usize, Sw> {
        self.events.push("read");
        assert!(self.response_open);
        if matches!(self.failure, Some(Failure::Read)) {
            out.fill(0xee);
            return Err(Sw::COMMAND_NOT_ALLOWED);
        }
        assert_eq!(offset, self.next);
        self.reads += 1;
        if self.total == 32 {
            out.copy_from_slice(&self.digest[offset as usize..offset as usize + out.len()]);
        } else if self.generated != 0 {
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = ((offset as usize + i) * 17) as u8;
            }
        } else {
            p.storage.read_at(Record::Pass, offset, out).unwrap();
        }
        self.next += out.len() as u32;
        Ok(out.len())
    }
    fn close_response(&mut self, _: &mut Platform<'_, impl canokey_ports::Backends>) {
        self.events.push("close");
        if self.response_open {
            self.closes += 1;
            self.response_open = false;
        }
    }
}
struct FrameSource<'a> {
    remaining: &'a [u8],
    closes: usize,
    close_error: Option<Sw>,
}
impl canokey_rust_core::runtime::engine::InputSource for FrameSource<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Sw> {
        let n = output.len().min(self.remaining.len());
        output[..n].copy_from_slice(&self.remaining[..n]);
        self.remaining = &self.remaining[n..];
        Ok(n)
    }
    fn close(&mut self) -> Result<(), Sw> {
        self.closes += 1;
        self.close_error.map_or(Ok(()), Err)
    }
}
fn frame(
    runtime: &mut Runtime<Fixture>,
    bytes: &[u8],
    p: &mut Platform<'_, impl canokey_ports::Backends>,
) -> Vec<u8> {
    if bytes[1] == 3 {
        let mut source = FrameSource {
            remaining: bytes,
            closes: 0,
            close_error: None,
        };
        let reply = runtime.receive_source(1, bytes.len(), &mut source, p);
        assert_eq!(source.closes, 1);
        let mut out = [0; 258];
        let n = runtime.transmit(reply, &mut out, p).unwrap();
        return out[..n].to_vec();
    }
    runtime.begin_frame(1, bytes.len(), p).unwrap();
    assert!(!runtime.can_preempt());
    // Model USB packets, including a split header, using the production entrypoint.
    for part in bytes.chunks(3) {
        runtime.feed_frame(part, p).unwrap();
    }
    let reply = runtime.end_frame(p);
    let mut out = [0; 258];
    let n = runtime.transmit(reply, &mut out, p).unwrap();
    out[..n].to_vec()
}
fn run(ins: u8, body: &[u8], chunk: usize) -> (Fixture, StorageBackend, Vec<u8>) {
    let mut storage = StorageBackend::default();
    let mut crypto = CryptoBackend;
    let mut device = DeviceBackend;
    let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut storage,
        crypto: &mut crypto,
        device: &mut device,
        memory: &MemoryBackend,
    };
    let mut runtime = Runtime::with_router(Fixture::new());
    assert_eq!(
        frame(&mut runtime, &[0x00, 0xa4, 0x04, 0x00, 0x01, 0x01], &mut p),
        [0x90, 0x00]
    );
    let mut response = if body.is_empty() {
        frame(&mut runtime, &[0x00, ins, 0x00, 0x00], &mut p)
    } else {
        let mut response = Vec::new();
        let parts: Vec<_> = body.chunks(chunk).collect();
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let mut command = vec![
                if last { 0x00 } else { 0x10 },
                ins,
                0x00,
                0x00,
                part.len() as u8,
            ];
            command.extend_from_slice(part);
            response = frame(&mut runtime, &command, &mut p);
            if !last {
                assert_eq!(response, [0x90, 0x00]);
                assert_eq!(runtime.router().finishes, 0);
                assert!(!runtime.can_preempt());
            }
        }
        response
    };
    let mut result = Vec::new();
    loop {
        let n = response.len();
        let sw = u16::from_be_bytes([response[n - 2], response[n - 1]]);
        result.extend_from_slice(&response[..n - 2]);
        if sw == 0x9000 {
            break;
        }
        assert_eq!(sw >> 8, 0x61);
        assert!(!runtime.can_preempt());
        response = frame(&mut runtime, &[0x00, 0xc0, 0x00, 0x00, 0x61], &mut p);
    }
    assert_eq!(runtime.router().finishes, 1);
    assert!(runtime.can_preempt());
    // Move the host fixture out without granting mutable access to runtime state.
    let router = runtime.into_router(&mut p);
    (router, storage, result)
}
#[test]
fn key_template_exceeds_frame_buffer() {
    let mut bytes = Vec::new();
    let mut expected = Sha256::new();
    for tag in 1..=5 {
        bytes.extend_from_slice(&[tag, 0x82, 0x01, 0x00]);
        let component = [tag; 256];
        bytes.extend_from_slice(&component);
        expected.update(component);
    }
    // Two-byte APDUs exercise a normal length field continuing into the next APDU.
    let (r, _, response) = run(1, &bytes, 2);
    assert_eq!(r.key_digest, <[u8; 32]>::from(expected.finalize()));
    assert!(response.is_empty());
    assert_eq!(r.frames, 650);
}
#[test]
fn long_message_is_hashed_during_receive() {
    let bytes = vec![b'a'; 8192];
    let (r, _, out) = run(2, &bytes, 233);
    assert_eq!(out, Sha256::digest(&bytes).to_vec());
    assert_eq!(r.closes, 1);
}
#[test]
fn large_object_stream_commits_once_then_reads_in_chunks() {
    let bytes: Vec<_> = (0..16384).map(|i| i as u8).collect();
    let (r, s, out) = run(3, &bytes, 241);
    assert_eq!(s.commits, 1);
    assert_eq!(s.object, bytes);
    assert_eq!(out, bytes);
    assert!(r.reads > 1);
    assert_eq!(r.closes, 1);
}
#[test]
fn generated_response_does_not_reexecute_operation() {
    let (r, _, out) = run(4, &[], 1);
    let expected: Vec<_> = (0..4096).map(|i| (i * 17) as u8).collect();
    assert_eq!(out, expected);
    assert_eq!(r.generated, 1);
    assert_eq!(r.closes, 1);
    assert!(r.reads > 1);
    assert!(core::mem::size_of::<Runtime<Fixture>>() < 2048);
}

#[test]
fn frame_decoder_owns_select_parameters_and_final_command_header() {
    for split in 0..=6 {
        let mut storage = StorageBackend::default();
        let mut crypto = CryptoBackend;
        let mut device = DeviceBackend;
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &MemoryBackend,
        };
        let mut runtime = Runtime::with_router(Fixture::new());
        for p2 in [1, 0] {
            let select = [0, 0xa4, 4, p2, 1, 1];
            runtime.begin_frame(1, select.len(), &mut p).unwrap();
            runtime.feed_frame(&select[..split], &mut p).unwrap();
            runtime.feed_frame(&select[split..], &mut p).unwrap();
            let reply = runtime.end_frame(&mut p);
            let mut out = [0; 258];
            let n = runtime.transmit(reply, &mut out, &mut p).unwrap();
            assert_eq!(
                &out[..n],
                if p2 == 0 {
                    &[0x90, 0][..]
                } else {
                    &[0x6a, 0x86][..]
                }
            );
            assert_eq!(runtime.router().selected, p2 == 0);
        }
        for last in [false, true] {
            let header = [if last { 0x80 } else { 0x90 }, 4, 0x12, 0x34];
            runtime.begin_frame(1, header.len(), &mut p).unwrap();
            for byte in header {
                runtime.feed_frame(&[byte], &mut p).unwrap();
            }
            let reply = runtime.end_frame(&mut p);
            let mut out = [0; 258];
            runtime.transmit(reply, &mut out, &mut p).unwrap();
            assert_eq!(runtime.router().last_frame, last);
            assert_eq!(runtime.router().finishes, usize::from(last));
        }
        assert_eq!(
            runtime.router().finished_header,
            Some(Header {
                cla: 0x80,
                ins: 4,
                p1: 0x12,
                p2: 0x34
            })
        );
        assert_eq!(runtime.router().generated, 1);
        runtime.reset(&mut p);
        assert_eq!(runtime.router().closes, 1);
    }
}

#[cfg(feature = "ctap")]
#[test]
fn fido_chain_exact_limit_overflow_and_recovery() {
    use canokey_rust_core::Core;
    for owner in [1, 3, 4] {
        for length in [1023, 1024, 1025, 1295, 1296] {
            for overflow in [false, true] {
                let (mut storage, mut crypto, mut device) =
                    (StorageBackend::default(), CryptoBackend, DeviceBackend);
                let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut storage,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &MemoryBackend,
                };
                let mut core = Core::new();
                let mut out = [0; 258];
                let mut select = [0, 0xa4, 4, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
                select[5..].copy_from_slice(if owner == 4 {
                    &canokey_protocol::apdu::FIDO_AID
                } else {
                    &canokey_protocol::apdu::FIDO_USB_AID
                });
                let reply = core.receive(owner, &select, &mut p);
                core.transmit(reply, &mut out, &mut p).unwrap();
                // getPinRetries plus an ignored byte string at each capacity boundary.
                let padding = length - 9;
                let mut request = vec![6, 0xa2, 2, 1, 0x18, 99, 0x59];
                request.extend_from_slice(&(padding as u16).to_be_bytes());
                request.resize(length, 0x37);
                for (index, bytes) in request.chunks(255).enumerate() {
                    let final_chunk = (index + 1) * 255 >= length && !overflow;
                    let mut frame = vec![
                        if final_chunk { 0x80 } else { 0x90 },
                        0x10,
                        0,
                        0,
                        bytes.len() as u8,
                    ];
                    frame.extend_from_slice(bytes);
                    let reply = core.receive(owner, &frame, &mut p);
                    let n = core.transmit(reply, &mut out, &mut p).unwrap();
                    assert_eq!(
                        &out[..n],
                        if final_chunk {
                            &[0, 0xa1, 3, 8, 0x90, 0][..]
                        } else {
                            &[0x90, 0][..]
                        }
                    );
                    assert_eq!(core.can_preempt(), final_chunk);
                }
                if overflow {
                    // Complete the chain budget, then exceed it by one byte.
                    let remaining = canokey_protocol::ctaphid::CTAP_MAX_REQUEST - length;
                    for bytes in vec![0; remaining].chunks(255) {
                        let mut frame = vec![0x90, 0x10, 0, 0, bytes.len() as u8];
                        frame.extend_from_slice(bytes);
                        let reply = core.receive(owner, &frame, &mut p);
                        let n = core.transmit(reply, &mut out, &mut p).unwrap();
                        assert_eq!(&out[..n], &[0x90, 0]);
                    }
                    let reply = core.receive(owner, &[0x90, 0x10, 0, 0, 1, 0], &mut p);
                    let n = core.transmit(reply, &mut out, &mut p).unwrap();
                    assert_eq!(&out[..n], &[0x67, 0]);
                    assert!(core.can_preempt());
                }
                let reply = core.receive(owner, &[0x80, 0x10, 0, 0, 4, 6, 0xa1, 2, 1], &mut p);
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                assert_eq!(&out[..n], &[0, 0xa1, 3, 8, 0x90, 0]);
                assert!(core.can_preempt());
            }
        }
    }
}

#[cfg(feature = "ctap")]
#[test]
fn extended_nfc_source_is_bounded_releases_before_crypto_and_resets_old_chain() {
    use canokey_rust_core::{Core, runtime::engine::InputSource};
    use std::{cell::Cell, rc::Rc};
    struct Probe(Rc<Cell<bool>>, usize);
    impl Crypto for Probe {
        fn key_operation(
            &mut self,
            op: KeyOperation,
            _: u8,
            key: &mut KeyMaterial,
            _: &[u8],
            out: &mut [u8],
        ) -> Result<usize, CryptoError> {
            assert!(
                !self.0.get(),
                "crypto must not run while NFC PKE input is live"
            );
            self.1 += 1;
            match op {
                KeyOperation::Generate => {
                    key.bytes[..32].fill(7);
                    Ok(0)
                }
                KeyOperation::Public => {
                    out[..64].fill(8);
                    Ok(64)
                }
                _ => Err(CryptoError::Failure),
            }
        }
        fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
            Err(CryptoError::Failure)
        }
        fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
            assert!(!self.0.get());
            out.fill(9);
            Ok(())
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            unreachable!()
        }
    }
    struct Source {
        bytes: Vec<u8>,
        offset: usize,
        held: Rc<Cell<bool>>,
        closes: usize,
        fail: bool,
    }
    impl InputSource for Source {
        fn read(&mut self, out: &mut [u8]) -> Result<usize, Sw> {
            assert!(self.held.get());
            if self.fail {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            out.copy_from_slice(&self.bytes[self.offset..self.offset + out.len()]);
            self.offset += out.len();
            Ok(out.len())
        }
        fn close(&mut self) -> Result<(), Sw> {
            assert!(self.held.replace(false));
            self.bytes.fill(0);
            self.closes += 1;
            Ok(())
        }
    }
    let held = Rc::new(Cell::new(false));
    let (mut storage, mut crypto, mut device, memory) = (
        StorageBackend::default(),
        Probe(held.clone(), 0),
        DeviceBackend,
        MemoryBackend,
    );
    let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut storage,
        crypto: &mut crypto,
        device: &mut device,
        memory: &memory,
    };
    let mut core = Core::new();
    let mut out = [0; 258];
    let prefix = [0x80, 0x10, 0, 0, 0, 1, 0x23]; // Lc=291, BE.
    assert_eq!(core.prepare_nfc(&prefix, &mut p), Err(Sw::FILE_NOT_FOUND));
    let select = b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x06\x47\x2f\x00\x01\x00";
    let reply = core.receive(4, select, &mut p);
    assert_eq!(core.transmit(reply, &mut out, &mut p).unwrap(), 8);
    for (head, expected) in [
        ([0x90, 0x10, 0, 0, 0, 1, 0x23], Sw::WRONG_LENGTH),
        ([0x81, 0xda, 0, 0, 0, 1, 0x23], Sw::WRONG_LENGTH),
        ([0x80, 0x10, 1, 0, 0, 1, 0x23], Sw::WRONG_P1P2),
        ([0x80, 0x10, 0, 1, 0, 1, 0x23], Sw::WRONG_P1P2),
    ] {
        assert_eq!(core.prepare_nfc(&head, &mut p), Err(expected));
    }
    // An NFC standalone command abandons an unfinished ISO command chain.
    let reply = core.receive(4, &[0x90, 0x10, 0, 0, 1, 6], &mut p);
    assert_eq!(core.transmit(reply, &mut out, &mut p).unwrap(), 2);
    assert_eq!(
        core.prepare_nfc(&prefix, &mut p),
        Ok(canokey_protocol::ctaphid::CTAP_MAX_REQUEST as u32)
    );
    let mut data = Vec::from(prefix);
    // getKeyAgreement plus a 280-byte ignored CBOR string, total CTAP body291.
    data.extend_from_slice(&[6, 0xa3, 1, 1, 2, 2, 0x18, 99, 0x59, 1, 0x18]);
    data.extend_from_slice(&[0x37; 280]);
    data.extend_from_slice(&[1, 0x23]);
    held.set(true);
    let mut source = Source {
        bytes: data,
        offset: 0,
        held: held.clone(),
        closes: 0,
        fail: false,
    };
    let (reply, info) = core.receive_source_with_info(4, source.bytes.len(), &mut source, &mut p);
    assert_eq!(source.closes, 1);
    assert!(source.bytes.iter().all(|b| *b == 0));
    assert_eq!(info.unwrap().le, Some(291));
    let n = core.transmit(reply, &mut out, &mut p).unwrap();
    assert_eq!(out[0], 0);
    assert_eq!(&out[n - 2..n], &[0x90, 0]);
    assert_eq!(p.crypto.1, 2);
    assert_eq!(
        core.prepare_nfc(&prefix, &mut p),
        Ok(canokey_protocol::ctaphid::CTAP_MAX_REQUEST as u32)
    );
    held.set(true);
    source.fail = true;
    let reply = core.receive_source(4, 300, &mut source, &mut p);
    assert_eq!(source.closes, 2);
    let n = core.transmit(reply, &mut out, &mut p).unwrap();
    assert_eq!(&out[..n], &[0x69, 0]);
}

#[cfg(feature = "ctap")]
#[test]
fn fido_requires_select_after_startup_and_slot_reset() {
    use canokey_rust_core::Core;
    // FIDO AID, CBOR getPinRetries, U2F VERSION and an ISO-chained CBOR fragment.
    const SELECT_USB: &[u8] = b"\x00\xa4\x04\x00\x08\xf0CANOFID\x00";
    const SELECT_NFC: &[u8] = b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x06\x47\x2f\x00\x01\x00";
    const RETRIES: &[u8] = &[0x80, 0x10, 0, 0, 4, 6, 0xa1, 2, 1];
    const VERSION: &[u8] = &[0, 3, 0, 0, 0];
    const CHAIN: &[u8] = &[0x90, 0x10, 0, 0, 1, 6];
    // Standalone extended CBOR getPinRetries: two-byte Lc=4, no Le.
    const EXTENDED: &[u8] = &[0x80, 0x10, 0, 0, 0, 0, 4, 6, 0xa1, 2, 1];
    for owner in [1, 3, 4] {
        let mut storage = StorageBackend::default();
        let mut crypto = CryptoBackend;
        let mut device = DeviceBackend;
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &MemoryBackend,
        };
        let mut core = Core::new();
        let mut out = [0; 258];
        for _ in 0..2 {
            for command in [RETRIES, VERSION, CHAIN, EXTENDED] {
                let reply = core.receive(owner, command, &mut p);
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                assert_eq!(&out[..n], &[0x6a, 0x82]);
            }
            let reply = core.receive(
                owner,
                if owner == 4 { SELECT_NFC } else { SELECT_USB },
                &mut p,
            );
            let n = core.transmit(reply, &mut out, &mut p).unwrap();
            assert_eq!(&out[..n], b"U2F_V2\x90\x00");
            let reply = core.receive(owner, RETRIES, &mut p);
            let n = core.transmit(reply, &mut out, &mut p).unwrap();
            assert_eq!(&out[..n], &[0, 0xa1, 3, 8, 0x90, 0]);
            core.slot_power(&mut p);
        }
    }
}

#[cfg(feature = "ctap")]
#[test]
fn long_select_aids_defer_p2_and_deselect_until_complete_input() {
    use canokey_protocol::apdu::{FIDO_AID, FIDO_USB_AID};
    use canokey_rust_core::Core;
    const VERSION: &[u8] = &[0, 3, 0, 0, 0];
    for owner in [1, 3, 4] {
        for length in [16, 17, 255] {
            for p2 in 0..=u8::MAX {
                let mut storage = StorageBackend::default();
                let mut crypto = CryptoBackend;
                let mut device = DeviceBackend;
                let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut storage,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &MemoryBackend,
                };
                let mut core = Core::new();
                let mut out = [0; 258];
                let mut select = vec![0, 0xa4, 4, 0, 8];
                select.extend_from_slice(if owner == 4 { &FIDO_AID } else { &FIDO_USB_AID });
                let reply = core.receive(owner, &select, &mut p);
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                assert_eq!(&out[..n], b"U2F_V2\x90\x00");
                let mut probe = vec![0, 0xa4, 4, p2, length];
                probe.resize(5 + usize::from(length), 0x5a);
                let reply = core.receive(owner, &probe, &mut p);
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                let sw = if p2 == 0 {
                    Sw::FILE_NOT_FOUND
                } else {
                    Sw::WRONG_P1P2
                };
                assert_eq!(&out[..n], sw.bytes(), "owner={owner} len={length} p2={p2}");
                let reply = core.receive(owner, VERSION, &mut p);
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                let absent = Sw::FILE_NOT_FOUND.bytes();
                assert_eq!(
                    &out[..n],
                    if owner == 4 {
                        &b"U2F_V2\x90\x00"[..]
                    } else {
                        &absent[..]
                    },
                    "owner={owner} len={length} p2={p2}"
                );
            }
        }
    }
}

#[cfg(feature = "ctap")]
#[test]
fn long_select_fragmentation_distinguishes_rejected_and_truncated_commands() {
    use canokey_protocol::apdu::{FIDO_AID, FIDO_USB_AID};
    use canokey_rust_core::{Core, runtime::engine::Reply};
    for owner in [1, 3, 4] {
        for length in [17, 255] {
            for chunk in [1, 16, 64] {
                for complete in [false, true] {
                    for p2 in [0, 0xff] {
                        let mut storage = StorageBackend::default();
                        let mut crypto = CryptoBackend;
                        let mut device = DeviceBackend;
                        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                            storage: &mut storage,
                            crypto: &mut crypto,
                            device: &mut device,
                            memory: &MemoryBackend,
                        };
                        let mut core = Core::new();
                        let mut exchange = |core: &mut Core, request: &[u8]| {
                            core.begin_frame(owner, request.len(), &mut p).unwrap();
                            let mut failure = None;
                            for bytes in request.chunks(chunk) {
                                if let Err(sw) = core.feed_frame(bytes, &mut p) {
                                    failure = Some(Reply::Status(sw));
                                    break;
                                }
                            }
                            let reply = failure.unwrap_or_else(|| core.end_frame(&mut p));
                            let mut out = [0; 258];
                            let n = core.transmit(reply, &mut out, &mut p).unwrap();
                            out[..n].to_vec()
                        };
                        let mut select = vec![0, 0xa4, 4, 0, 8];
                        select.extend_from_slice(if owner == 4 {
                            &FIDO_AID
                        } else {
                            &FIDO_USB_AID
                        });
                        assert_eq!(exchange(&mut core, &select), b"U2F_V2\x90\x00");
                        let mut probe = vec![0, 0xa4, 4, p2, length];
                        probe.resize(5 + usize::from(length) - usize::from(!complete), 0x5a);
                        let sw = if !complete {
                            Sw::WRONG_LENGTH
                        } else if p2 != 0 {
                            Sw::WRONG_P1P2
                        } else {
                            Sw::FILE_NOT_FOUND
                        };
                        assert_eq!(exchange(&mut core, &probe), sw.bytes());
                        let absent = Sw::FILE_NOT_FOUND.bytes();
                        let expected = if !complete || owner == 4 {
                            &b"U2F_V2\x90\x00"[..]
                        } else {
                            &absent[..]
                        };
                        assert_eq!(exchange(&mut core, &[0, 3, 0, 0, 0]), expected);
                    }
                }
            }
        }
    }
}

#[test]
fn failed_frame_execution_and_read_preserve_cleanup_order_and_release_ownership() {
    for (failure, status, expected) in [
        (Failure::EndFrame, Sw::WRONG_DATA, &["end", "abort"][..]),
        (
            Failure::Finish,
            Sw::WRONG_P1P2,
            &["end", "finish", "abort", "close"][..],
        ),
        (
            Failure::Read,
            Sw::COMMAND_NOT_ALLOWED,
            &["end", "finish", "read", "close"][..],
        ),
    ] {
        let mut storage = StorageBackend::default();
        let mut crypto = CryptoBackend;
        let mut device = DeviceBackend;
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &MemoryBackend,
        };
        let mut fixture = Fixture::new();
        fixture.failure = Some(failure);
        let mut runtime = Runtime::with_router(fixture);
        assert_eq!(
            frame(&mut runtime, &[0, 0xa4, 4, 0, 1, 1], &mut p),
            [0x90, 0]
        );
        let reply = runtime.receive(1, &[0, 4, 0, 0], &mut p);
        let mut out = [0xa5; 258];
        let n = runtime.transmit(reply, &mut out, &mut p).unwrap();
        assert_eq!(&out[..n], status.bytes());
        assert!(runtime.router().events.ends_with(expected));
        assert!(!runtime.router().response_open);
        assert!(runtime.can_preempt());
        if matches!(failure, Failure::Read) {
            // A source may write sensitive bytes before reporting an error.
            assert!(out[2..256].iter().all(|&byte| byte == 0));
            assert_eq!(runtime.router().closes, 1);
        }
        // The failed response cannot be resumed or cause another source read.
        let reads = runtime
            .router()
            .events
            .iter()
            .filter(|&&event| event == "read")
            .count();
        assert_eq!(
            frame(&mut runtime, &[0, 0xc0, 0, 0, 16], &mut p),
            Sw::COMMAND_NOT_ALLOWED.bytes()
        );
        assert_eq!(
            runtime
                .router()
                .events
                .iter()
                .filter(|&&event| event == "read")
                .count(),
            reads
        );
    }
}

#[test]
fn source_close_failure_blocks_commit_even_after_complete_input_and_overrides_parse_error() {
    // The second command declares two bytes but supplies only one. Closing a
    // cancelled source must also win over this earlier framing error.
    for bytes in [&[0, 3, 0, 0, 2, 0xaa, 0xbb][..], &[0, 3, 0, 0, 2, 0xaa][..]] {
        let (mut storage, mut crypto, mut device) =
            (StorageBackend::default(), CryptoBackend, DeviceBackend);
        let mut p = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &MemoryBackend,
        };
        let mut runtime = Runtime::with_router(Fixture::new());
        assert_eq!(
            frame(&mut runtime, &[0, 0xa4, 4, 0, 1, 1], &mut p),
            [0x90, 0]
        );
        let mut source = FrameSource {
            remaining: bytes,
            closes: 0,
            close_error: Some(Sw::UNABLE_TO_PROCESS),
        };
        let reply = runtime.receive_source(1, bytes.len(), &mut source, &mut p);
        let mut out = [0; 258];
        let n = runtime.transmit(reply, &mut out, &mut p).unwrap();
        assert_eq!(&out[..n], &[0x69, 0]);
        assert_eq!(source.closes, 1);
        assert_eq!(runtime.router().finishes, 0);
        assert_eq!(p.storage.commits, 0);
        assert!(p.storage.object.is_empty());
        assert!(runtime.can_preempt());
    }
}
