// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ctap")]
use canokey_protocol::ctaphid::{self as wire, Error};
use canokey_rust_core::runtime::ctaphid::{Scratch, Transport};
#[path = "support/ctap.rs"]
mod support;

#[derive(Default)]
struct Memory {
    disabled: bool,
    bytes: Vec<u8>,
    response: Vec<u8>,
    closes: usize,
    reads: Vec<(usize, usize)>,
    leased: bool,
    busy: bool,
    fail: bool,
    fail_read: bool,
    response_length: Option<usize>,
    response_failure: bool,
    response_closes: usize,
    request: Option<canokey_rust_core::applets::ctap::Request>,
    message: Option<canokey_rust_core::applets::ctap::apdu::MessageParser>,
}
impl Scratch for Memory {
    fn webauthn_enabled(&mut self) -> bool {
        !self.disabled
    }
    fn begin(&mut self, pke: bool) -> Result<(), Error> {
        assert!(!self.leased);
        if self.busy {
            return Err(Error::Busy);
        }
        self.leased = true;
        if pke {
            self.bytes.resize(1033, 0);
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        assert!(self.leased);
        if self.fail {
            return Err(Error::Other);
        }
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        assert!(self.leased);
        if self.fail {
            return Err(Error::Other);
        }
        if self.fail_read {
            return Err(Error::Other);
        }
        self.reads.push((offset, bytes.len()));
        bytes.copy_from_slice(&self.bytes[offset..offset + bytes.len()]);
        Ok(())
    }
    fn begin_request(&mut self, message_length: Option<usize>) {
        if let Some(length) = message_length {
            self.message = Some(canokey_rust_core::applets::ctap::apdu::MessageParser::new(
                length,
            ));
        } else {
            self.request = Some(canokey_rust_core::applets::ctap::Request::new());
        }
    }
    fn consume_request(&mut self, bytes: &[u8]) {
        if let Some(request) = &mut self.request {
            request.consume(bytes);
        }
        if let Some(request) = &mut self.message {
            request.consume(bytes);
        }
    }
    fn finish_request(&mut self, cid: u32) -> usize {
        if let Some(mut request) = self.request.take() {
            self.execute(cid, request.finish())
        } else {
            let command = self.message.take().unwrap().finish();
            self.execute_message(cid, command)
        }
    }
    fn wink(&mut self, cid: u32) -> usize {
        self.execute(cid, Ok(canokey_rust_core::applets::ctap::Command::Wink))
    }
    fn read_response(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        if self.response_failure {
            return Err(Error::Other);
        }
        out.copy_from_slice(&self.response[offset..offset + out.len()]);
        Ok(())
    }
    fn close_response(&mut self) {
        self.response_closes += 1;
        self.request = None;
        self.message = None;
        self.response.clear();
    }
    fn close(&mut self) {
        assert!(self.leased, "source must close exactly once");
        self.leased = false;
        self.closes += 1;
        self.bytes.fill(0);
    }
}
// Build input independently of the production encoder.
fn initial(cid: u32, cmd: u8, length: usize, payload: &[u8]) -> [u8; 64] {
    let mut frame = [0; 64];
    frame[..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = cmd;
    frame[5] = (length >> 8) as u8;
    frame[6] = length as u8;
    frame[7..7 + payload.len()].copy_from_slice(payload);
    frame
}
fn continuation(cid: u32, seq: u8, data: &[u8]) -> [u8; 64] {
    let mut frame = [0; 64];
    frame[..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = seq;
    frame[5..5 + data.len()].copy_from_slice(data);
    frame
}
fn request(hid: &mut Transport, memory: &mut Memory, command: u8, body: &[u8]) {
    let mut out = [0; 64];
    let first = body.len().min(57);
    assert!(!hid.receive(
        &initial(0x12345678, command, body.len(), &body[..first]),
        0,
        &mut out,
        memory
    ));
    for (seq, part) in body[first..].chunks(59).enumerate() {
        assert!(!hid.receive(
            &continuation(0x12345678, seq as u8, part),
            seq as u32 + 1,
            &mut out,
            memory
        ));
    }
}

#[test]
fn ping_boundaries_and_monotonic_source_lifetime() {
    for length in [0, 57, 58, 192, 193, 1024] {
        let mut hid = Transport::new();
        let mut memory = Memory::default();
        let body: Vec<u8> = (0..length).map(|n| (n * 37) as u8).collect();
        request(&mut hid, &mut memory, wire::PING, &body);
        let mut result = Vec::new();
        let mut out = [0; 64];
        let mut reports = 0;
        while hid.transmit(&mut out, &mut memory) {
            assert_eq!(&out[..4], &[0x12, 0x34, 0x56, 0x78]);
            let start = if reports == 0 {
                assert_eq!(&out[4..7], &[0x81, (length >> 8) as u8, length as u8]);
                7
            } else {
                assert_eq!(out[4], reports - 1);
                5
            };
            result.extend_from_slice(&out[start..start + (length - result.len()).min(64 - start)]);
            reports += 1;
        }
        assert_eq!(result, body);
        assert!(hid.active());
        assert_eq!(memory.closes, 0); // final report still in flight
        hid.completed(&mut memory);
        hid.completed(&mut memory);
        assert!(!hid.active());
        assert_eq!(memory.closes, 1);
        if length > 192 {
            let mut offset = 0;
            for (at, n) in memory.reads {
                assert_eq!(at, offset);
                offset += n;
            }
            assert_eq!(offset, length);
        } else {
            assert!(memory.reads.is_empty());
        }
    }
}

#[test]
fn channel_contention_resync_sequence_and_wrapping_timeout() {
    let mut hid = Transport::new();
    let mut mem = Memory::default();
    let mut out = [0; 64];
    let start = initial(0x12345678, wire::PING, 193, &[1; 57]);
    assert!(!hid.receive(&start, u32::MAX - 99, &mut out, &mut mem));
    assert!(hid.receive(&initial(2, wire::PING, 0, &[]), 0, &mut out, &mut mem));
    assert_eq!(&out[..8], &[0, 0, 0, 2, 0xbf, 0, 1, 6]);
    assert_eq!(mem.closes, 0);
    assert!(!hid.timeout(699, &mut out, &mut mem));
    assert!(hid.timeout(700, &mut out, &mut mem));
    assert_eq!(out[7], 5);
    assert_eq!(mem.closes, 1);
    assert!(!hid.receive(&start, 0, &mut out, &mut mem));
    assert!(hid.receive(
        &continuation(0x12345678, 1, &[0; 59]),
        1,
        &mut out,
        &mut mem
    ));
    assert_eq!(out[7], 4);
    assert!(!hid.receive(&start, 2, &mut out, &mut mem));
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    assert!(hid.receive(
        &initial(0x12345678, wire::INIT, 8, &nonce),
        3,
        &mut out,
        &mut mem
    ));
    assert_eq!(
        &out[7..24],
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 0x12, 0x34, 0x56, 0x78, 2, 0, 0, 0, 0x05
        ]
    );
    assert_eq!(mem.closes, 3);
    hid.reset(&mut mem);
    assert_eq!(mem.closes, 3);
}

#[test]
fn failures_release_only_owned_storage() {
    let mut hid = Transport::new();
    let mut mem = Memory {
        busy: true,
        ..Memory::default()
    };
    let mut out = [0; 64];
    let start = initial(1, wire::PING, 193, &[1; 57]);
    assert!(hid.receive(&start, 0, &mut out, &mut mem));
    assert_eq!(out[7], 6);
    assert_eq!(mem.closes, 0);
    mem.busy = false;
    mem.fail = true;
    assert!(hid.receive(&start, 0, &mut out, &mut mem));
    assert_eq!(out[7], 0x7f);
    assert_eq!(mem.closes, 1);
    mem.fail = false;
    request(&mut hid, &mut mem, wire::PING, &[0; 193]);
    mem.fail = true;
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(out[7], 0x7f);
    assert_eq!(mem.closes, 2);
    hid.reset(&mut mem);
    assert_eq!(mem.closes, 2);
}

#[test]
fn cbor_releases_input_before_response_and_cancel_is_silent() {
    let mut hid = Transport::new();
    let mut mem = Memory::default();
    let mut out = [0; 64];
    assert!(!hid.receive(&initial(1, wire::CANCEL, 0, &[]), 0, &mut out, &mut mem));
    request(&mut hid, &mut mem, wire::CBOR, &[0x04]);
    assert_eq!(mem.closes, 1);
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(
        &out[9..20],
        &[
            1, 0x84, 0x66, b'U', b'2', b'F', b'_', b'V', b'2', 0x68, b'F'
        ]
    );
    hid.completed(&mut mem);
    assert_eq!(mem.closes, 1);
    while hid.transmit(&mut out, &mut mem) {
        hid.completed(&mut mem);
    }
    request(&mut hid, &mut mem, wire::CBOR, &[0x7f; 193]);
    assert_eq!(mem.closes, 2);
    assert_eq!(mem.reads, [(0, 192), (192, 1)]);
    assert!(!mem.leased);
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(&out[4..8], &[0x90, 0, 1, 1]);
    hid.completed(&mut mem);
    let mut query = vec![6, 0xa2, 2, 1, 0x18, 99, 0x58, 200];
    query.extend_from_slice(&[0x37; 200]);
    request(&mut hid, &mut mem, wire::CBOR, &query);
    assert_eq!(mem.closes, 3);
    assert!(!mem.leased);
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(&out[4..11], &[0x90, 0, 4, 0, 0xa1, 3, 8]);
    hid.completed(&mut mem);
    // A crypto command with a large ignored extension must also close PKE
    // before execution. The mock executor asserts that boundary explicitly.
    let mut agreement = vec![6, 0xa3, 1, 1, 2, 2, 0x18, 99, 0x59, 2, 0xbc];
    agreement.extend_from_slice(&[0; 700]);
    request(&mut hid, &mut mem, wire::CBOR, &agreement);
    assert_eq!(mem.closes, 4);
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(&out[7..11], &[0, 0xa1, 1, 0xa5]);
    hid.completed(&mut mem);
    assert!(hid.transmit(&mut out, &mut mem));
    hid.completed(&mut mem);
    assert!(!hid.active());
}

#[test]
fn apdu_input_abort_preserves_response_backing() {
    use canokey_protocol::apdu::Header;
    use canokey_rust_core::runtime::{engine::Router, registry::Registry};
    let mut ctap = Registry::new();
    support::with_platform(&mut support::Backend::default(), |p| {
        ctap.select(canokey_rust_core::applets::ctap::apdu::AID, p)
            .unwrap();
        ctap.consume(&[], p).unwrap();
        ctap.consume(&[0x04], p).unwrap();
        ctap.consume(&[], p).unwrap();
        let h = Header {
            cla: 0x80,
            ins: 0x10,
            p1: 0,
            p2: 0,
        };
        assert!(ctap.finish(h, 0, p).unwrap().0 > 0);
        ctap.abort_command(p);
        let mut prefix = [0; 8];
        ctap.read_response(2, &mut prefix, p).unwrap();
        assert_eq!(prefix, [1, 0x84, 0x66, b'U', b'2', b'F', b'_', b'V']);
        ctap.close_response(p);
        assert!(ctap.read_response(0, &mut prefix, p).is_err());
    });
}

#[test]
fn msg_apdu_status_and_source_release() {
    for (body, expected) in [
        (vec![0, 3, 0, 0], b"U2F_V2\x90\x00".to_vec()),
        (vec![0, 3, 0, 0, 0, 0, 0], b"U2F_V2\x90\x00".to_vec()),
        (vec![0, 3, 0], vec![0x67, 0]),
        (vec![0x81, 3, 0, 0], vec![0x6e, 0]),
        // Extended input exceeds the inline area; parsing closes PKE before execution.
        (
            [vec![0, 3, 0, 0, 0, 1, 0], vec![0; 256]].concat(),
            vec![0x67, 0],
        ),
        (vec![0x80, 0x10, 0, 0, 1, 0x7f], vec![1, 0x90, 0]),
    ] {
        let mut hid = Transport::new();
        let mut memory = Memory::default();
        request(&mut hid, &mut memory, wire::MSG, &body);
        assert_eq!(memory.closes, 1);
        let mut out = [0; 64];
        assert!(hid.transmit(&mut out, &mut memory));
        assert_eq!(&out[4..7], &[wire::MSG, 0, expected.len() as u8]);
        assert_eq!(&out[7..7 + expected.len()], expected);
        hid.completed(&mut memory);
        assert_eq!(memory.closes, 1);
    }
}

#[test]
fn polling_presence_is_fresh_single_use_and_expires() {
    use canokey_rust_core::runtime::Polling;
    let mut touch = Polling::new();
    touch.sample(true, 0); // A preexisting hold must first be released.
    touch.sample(false, 10);
    assert!(!touch.take(10));
    touch.sample(true, 20);
    touch.sample(false, 30);
    assert!(touch.take(31));
    assert!(!touch.take(32));
    touch.sample(true, 40);
    touch.sample(false, 50);
    assert!(!touch.take(1050));
    touch.sample(true, u32::MAX - 2);
    touch.sample(false, u32::MAX);
    assert!(touch.take(1));
    touch.sample(true, 2);
    touch.sample(false, 3);
    touch.clear();
    assert!(!touch.take(4));
}

impl Memory {
    fn override_response(&mut self) -> Option<usize> {
        let length = self.response_length?;
        self.response = (0..length.min(wire::MAX_MESSAGE))
            .map(|i| (i * 13) as u8)
            .collect();
        Some(length)
    }
    fn execute(
        &mut self,
        _cid: u32,
        command: Result<
            canokey_rust_core::applets::ctap::Command,
            canokey_rust_core::applets::ctap::Status,
        >,
    ) -> usize {
        assert!(
            !self.leased,
            "crypto must execute only after source release"
        );
        if let Some(length) = self.override_response() {
            return length;
        }
        self.response = support::execute(&mut canokey_rust_core::Core::new(), command);
        self.response.len()
    }
    fn execute_message(
        &mut self,
        _: u32,
        command: canokey_rust_core::applets::ctap::apdu::Message,
    ) -> usize {
        assert!(
            !self.leased,
            "MSG crypto must execute only after source release"
        );
        if let Some(length) = self.override_response() {
            return length;
        }
        self.response = support::with_platform(&mut support::Backend::default(), |p| {
            let mut core = canokey_rust_core::Core::new();
            let n = core.execute_ctap_message(command, p);
            let mut out = vec![0; n];
            core.read_ctap(0, &mut out, p).unwrap();
            out
        });
        self.response.len()
    }
}

#[test]
fn parser_workspace_is_released_after_staged_read_failure() {
    for command in [wire::CBOR, wire::MSG] {
        let mut hid = Transport::new();
        let mut mem = Memory {
            fail_read: true,
            ..Memory::default()
        };
        let mut out = [0; 64];
        assert!(!hid.receive(&initial(1, command, 193, &[0; 57]), 0, &mut out, &mut mem));
        assert!(!hid.receive(&continuation(1, 0, &[0; 59]), 1, &mut out, &mut mem));
        assert!(!hid.receive(&continuation(1, 1, &[0; 59]), 2, &mut out, &mut mem));
        assert!(hid.receive(&continuation(1, 2, &[0; 18]), 3, &mut out, &mut mem));
        assert_eq!(out[7], 0x7f);
        assert!(!hid.active());
        assert!(!mem.leased);
        assert_eq!(mem.closes, 1);
        assert!(mem.request.is_none() && mem.message.is_none());
    }
}

#[test]
fn disabled_webauthn_rejects_cbor_and_msg_without_disabling_ping() {
    let mut hid = Transport::new();
    let mut memory = Memory {
        disabled: true,
        ..Memory::default()
    };
    let mut out = [0; 64];
    for command in [wire::CBOR, wire::MSG] {
        assert!(hid.receive(
            &initial(0x12345678, command, 1, &[4]),
            0,
            &mut out,
            &mut memory
        ));
        assert_eq!(&out[4..8], &[wire::ERROR, 0, 1, Error::Command as u8]);
        assert!(memory.request.is_none() && memory.message.is_none());
        assert!(!memory.leased);
    }
    request(&mut hid, &mut memory, wire::PING, &[1, 2, 3]);
    assert!(hid.transmit(&mut out, &mut memory));
    assert_eq!(&out[4..10], &[wire::PING, 0, 3, 1, 2, 3]);
}

#[test]
fn response_limits_and_read_failure_close_once() {
    for (command, body) in [
        (wire::CBOR, &[4][..]),
        (wire::MSG, &[0, 3, 0, 0, 0][..]),
        (wire::WINK, &[][..]),
    ] {
        for length in [
            0,
            1,
            57,
            58,
            wire::MAX_MESSAGE,
            wire::MAX_MESSAGE + 1,
            65536,
            usize::MAX,
        ] {
            for read_failure in [false, true] {
                let mut hid = Transport::new();
                let mut memory = Memory {
                    response_length: Some(length),
                    response_failure: read_failure,
                    ..Memory::default()
                };
                let mut out = [0; 64];
                let rejected = hid.receive(
                    &initial(1, command, body.len(), body),
                    0,
                    &mut out,
                    &mut memory,
                );
                if length > wire::MAX_MESSAGE {
                    assert!(rejected);
                    assert_eq!(&out[4..8], &[wire::ERROR, 0, 1, Error::Length as u8]);
                } else {
                    assert!(!rejected);
                    let mut offset = 0;
                    let mut frame = 0;
                    while hid.transmit(&mut out, &mut memory) {
                        if read_failure {
                            assert_eq!(&out[4..8], &[wire::ERROR, 0, 1, Error::Other as u8]);
                            break;
                        }
                        let start = if frame == 0 { 7 } else { 5 };
                        assert_eq!(
                            out[4],
                            if frame == 0 {
                                command
                            } else {
                                (frame - 1) as u8
                            }
                        );
                        if frame == 0 {
                            assert_eq!(u16::from_be_bytes([out[5], out[6]]) as usize, length);
                        }
                        let count = (length - offset).min(64 - start);
                        for i in 0..count {
                            assert_eq!(out[start + i], ((offset + i) * 13) as u8);
                        }
                        assert_eq!(memory.response_closes, 0);
                        offset += count;
                        frame += 1;
                        assert!(frame <= 129);
                        hid.completed(&mut memory);
                    }
                    if !read_failure {
                        assert_eq!(offset, length);
                    }
                }
                assert!(!hid.active());
                assert_eq!(memory.closes, 1);
                assert_eq!(memory.response_closes, 1);
                hid.reset(&mut memory);
                hid.completed(&mut memory);
                assert!(!hid.transmit(&mut out, &mut memory));
                assert_eq!(memory.response_closes, 1);
            }
        }
    }
}
