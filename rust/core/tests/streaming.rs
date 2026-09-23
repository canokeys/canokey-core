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
    fn load(&mut self, _: Record, out: &mut [u8]) -> Result<usize, StorageError> {
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
struct Fixture {
    sink: Sink,
    tlv: tlv::Decoder,
    selected: bool,
    frames: usize,
    finishes: usize,
    closes: usize,
    reads: usize,
    generated: usize,
    next: u32,
    total: u32,
    digest: [u8; 32],
    key_digest: [u8; 32],
    response_open: bool,
}
impl Fixture {
    fn new() -> Self {
        Self {
            sink: Sink::None,
            tlv: tlv::Decoder::default(),
            selected: false,
            frames: 0,
            finishes: 0,
            closes: 0,
            reads: 0,
            generated: 0,
            next: 0,
            total: 0,
            digest: [0; 32],
            key_digest: [0; 32],
            response_open: false,
        }
    }
}
impl Router for Fixture {
    fn install(&mut self, _: &mut Platform<'_>) -> Result<(), Sw> {
        Ok(())
    }
    fn reset(&mut self, _: &mut Platform<'_>) {
        self.selected = false;
    }
    fn selected(&self) -> bool {
        self.selected
    }
    fn select(&mut self, aid: &[u8], _: &mut Platform<'_>) -> Result<u32, Sw> {
        assert_eq!(aid, [1]);
        self.selected = true;
        Ok(0)
    }
    fn command_limit(&self, _: Header) -> Result<u32, Sw> {
        Ok(100_000)
    }
    fn abort_command(&mut self, _: &mut Platform<'_>) {
        self.sink = Sink::None;
        self.tlv = tlv::Decoder::default();
    }
    fn begin_command(&mut self, h: Header, _: &mut Platform<'_>) -> Result<(), Sw> {
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
    fn consume(&mut self, bytes: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
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
    fn end_frame(&mut self, _: bool, _: &mut Platform<'_>) -> Result<(), Sw> {
        self.frames += 1;
        Ok(())
    }
    fn finish(&mut self, h: Header, _: u32, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        self.finishes += 1;
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
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        assert!(self.response_open);
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
    fn close_response(&mut self, _: &mut Platform<'_>) {
        if self.response_open {
            self.closes += 1;
            self.response_open = false;
        }
    }
}
struct FrameSource<'a> {
    remaining: &'a [u8],
    closes: usize,
}
impl canokey_rust_core::runtime::engine::InputSource for FrameSource<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Sw> {
        let n = output.len().min(self.remaining.len());
        output[..n].copy_from_slice(&self.remaining[..n]);
        self.remaining = &self.remaining[n..];
        Ok(n)
    }
    fn close(&mut self) {
        self.closes += 1;
    }
}
fn frame(runtime: &mut Runtime<Fixture>, bytes: &[u8], p: &mut Platform<'_>) -> Vec<u8> {
    if bytes[1] == 3 {
        let mut source = FrameSource {
            remaining: bytes,
            closes: 0,
        };
        let reply = runtime.receive_source(1, bytes.len(), &mut source, p);
        assert_eq!(source.closes, 1);
        let mut out = [0; 258];
        let n = runtime.transmit(reply, &mut out, p).unwrap();
        return out[..n].to_vec();
    }
    runtime.begin_frame(1, bytes.len(), p).unwrap();
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
    let mut p = Platform {
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
        response = frame(&mut runtime, &[0x00, 0xc0, 0x00, 0x00, 0x61], &mut p);
    }
    assert_eq!(runtime.router().finishes, 1);
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

#[cfg(feature = "ctap")]
#[test]
fn extended_fido_source_is_bounded_and_ccid_only() {
    use canokey_rust_core::{Core, runtime::engine::InputSource};
    let (mut storage, mut crypto, mut device, memory) = (
        StorageBackend::default(),
        CryptoBackend,
        DeviceBackend,
        MemoryBackend,
    );
    let mut p = Platform {
        storage: &mut storage,
        crypto: &mut crypto,
        device: &mut device,
        memory: &memory,
    };
    let mut core = Core::new();
    let mut out = [0; 258];
    let prefix = [0x80, 0x10, 0, 0, 0, 1, 0x23]; // Lc=291, BE
    assert_eq!(
        core.prepare_extended(1, &prefix, 300, &mut p),
        Err(Sw::WRONG_LENGTH)
    );
    let select = [0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1, 0];
    let reply = core.receive(1, &select, &mut p);
    assert_eq!(core.transmit(reply, &mut out, &mut p).unwrap(), 10);
    for (owner, head, total) in [
        (2, prefix, 300),
        (1, [0x90, 0x10, 0, 0, 0, 1, 0x23], 300),
        (1, [0, 0xda, 0, 0, 0, 1, 0x23], 300),
        (1, prefix, 299),
        (1, [0x80, 0x10, 0, 0, 0, 4, 1], 1034),
    ] {
        assert_eq!(
            core.prepare_extended(owner, &head, total, &mut p),
            Err(Sw::WRONG_LENGTH)
        );
    }
    assert_eq!(core.prepare_extended(1, &prefix, 300, &mut p), Ok(291));
    let mut data = Vec::from(prefix);
    data.extend_from_slice(&[0x06; 291]);
    data.extend_from_slice(&[1, 0x23]); // Le=291, not a native-endian word
    let mut source = FrameSource {
        remaining: &data,
        closes: 0,
    };
    let reply = core.receive_source(1, data.len(), &mut source, &mut p);
    assert_eq!(source.closes, 1);
    let n = core.transmit(reply, &mut out, &mut p).unwrap();
    assert_eq!(&out[..n], &[1, 0x90, 0]); // unsupported CTAP command, accepted envelope

    // An extended command cannot finish an existing ISO input chain.
    let reply = core.receive(1, &[0x90, 0x10, 0, 0, 1, 4], &mut p);
    assert_eq!(core.transmit(reply, &mut out, &mut p).unwrap(), 2);
    assert_eq!(
        core.prepare_extended(1, &prefix, 300, &mut p),
        Err(Sw::WRONG_LENGTH)
    );
    core.reset(&mut p);
    let reply = core.receive(1, &select, &mut p);
    core.transmit(reply, &mut out, &mut p).unwrap();
    assert_eq!(core.prepare_extended(1, &prefix, 300, &mut p), Ok(291));
    struct Failed {
        closes: usize,
    }
    impl InputSource for Failed {
        fn read(&mut self, _: &mut [u8]) -> Result<usize, Sw> {
            Err(Sw::UNABLE_TO_PROCESS)
        }
        fn close(&mut self) {
            self.closes += 1;
        }
    }
    let mut failed = Failed { closes: 0 };
    let reply = core.receive_source(1, 300, &mut failed, &mut p);
    assert_eq!(failed.closes, 1);
    let n = core.transmit(reply, &mut out, &mut p).unwrap();
    assert_eq!(&out[..n], &[0x69, 0]);
}
