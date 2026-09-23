// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ctap")]
use canokey_protocol::ctaphid::{self as wire, Error};
use canokey_rust_core::runtime::ctaphid::{Scratch, Transport};

#[derive(Default)]
struct Memory {
    bytes: Vec<u8>,
    closes: usize,
    reads: Vec<(usize, usize)>,
    leased: bool,
    busy: bool,
    fail: bool,
}
impl Scratch for Memory {
    fn begin(&mut self, pke: bool) -> Result<(), Error> {
        assert!(!self.leased);
        if self.busy {
            return Err(Error::Busy);
        }
        self.leased = true;
        if pke {
            self.bytes.resize(1024, 0);
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
        self.reads.push((offset, bytes.len()));
        bytes.copy_from_slice(&self.bytes[offset..offset + bytes.len()]);
        Ok(())
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
            1, 2, 3, 4, 5, 6, 7, 8, 0x12, 0x34, 0x56, 0x78, 2, 0, 0, 0, 0x0c
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
        &out[7..21],
        &[
            0, 0xa5, 1, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0', 3
        ]
    );
    hid.completed(&mut mem);
    assert_eq!(mem.closes, 1);
    request(&mut hid, &mut mem, wire::CBOR, &[0x06; 193]);
    assert_eq!(mem.closes, 2);
    assert_eq!(mem.reads, [(0, 192), (192, 1)]);
    assert!(!mem.leased);
    assert!(hid.transmit(&mut out, &mut mem));
    assert_eq!(&out[4..8], &[0x90, 0, 1, 1]);
    hid.completed(&mut mem);
}

#[test]
fn apdu_input_abort_preserves_response_backing() {
    let mut ctap = canokey_rust_core::applets::ctap::apdu::Applet::new();
    ctap.consume(&[]).unwrap();
    ctap.consume(&[0x04]).unwrap();
    ctap.consume(&[]).unwrap();
    assert_eq!(ctap.finish().unwrap(), 51);
    ctap.cancel_command();
    let mut prefix = [0; 8];
    ctap.read(1, &mut prefix).unwrap();
    assert_eq!(prefix, [0xa5, 1, 0x81, 0x68, b'F', b'I', b'D', b'O']);
    ctap.close();
    assert!(ctap.read(0, &mut prefix).is_err());
}
