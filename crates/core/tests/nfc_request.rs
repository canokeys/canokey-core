// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::{apdu, response::StatusWord as Sw};
use canokey_rust_core::runtime::nfc::{
    Event, Link,
    request::{Backend, Rejection, Request},
};

struct Stage {
    data: Vec<u8>,
    prepare: usize,
    writes: usize,
    closes: usize,
    held: bool,
    fail: bool,
    rejection: Option<Rejection>,
}
impl Default for Stage {
    fn default() -> Self {
        Self {
            data: vec![0; 1296],
            prepare: 0,
            writes: 0,
            closes: 0,
            held: false,
            fail: false,
            rejection: None,
        }
    }
}
impl Backend for Stage {
    fn prepare(&mut self, prefix: &[u8; 7]) -> Result<(), Rejection> {
        self.prepare += 1;
        if let Some(rejection) = self.rejection {
            return Err(rejection);
        }
        if prefix[..2] != [0x80, 0x10] {
            return Err(Rejection::Status(Sw::WRONG_LENGTH));
        }
        assert!(!self.held);
        self.held = true;
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
        assert!(self.held);
        self.writes += 1;
        if self.fail {
            return false;
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        true
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool {
        assert!(self.held);
        out.copy_from_slice(&self.data[offset..offset + out.len()]);
        true
    }
    fn close(&mut self) {
        assert!(self.held);
        self.data.fill(0);
        self.held = false;
        self.closes += 1;
    }
}
fn envelope(cla: u8, body: usize, le: Option<u16>) -> Vec<u8> {
    let mut bytes = vec![cla, 0x10, 0, 0, 0];
    bytes.extend_from_slice(&(body as u16).to_be_bytes());
    bytes.extend((0..body).map(|n| n as u8));
    if let Some(le) = le {
        bytes.extend_from_slice(&le.to_be_bytes());
    }
    bytes
}
#[test]
fn inline_and_staged_envelopes_survive_every_split_and_bounded_read() {
    for body in [1, 254, 255, 279, 280, 281, 282, 1024, 1296] {
        for le in [None, Some(1), Some(256), Some(0)] {
            let bytes = envelope(0x80, body, le);
            for split in 0..=bytes.len() {
                let mut request = Request::new();
                let mut inline = [0; apdu::SHORT_FRAME_BYTES];
                let mut stage = Stage::default();
                request.append(&bytes[..split], &mut inline, &mut stage);
                request.append(&bytes[split..], &mut inline, &mut stage);
                assert_eq!(request.finish(&mut stage), Ok(()));
                let mut actual = Vec::new();
                while actual.len() < bytes.len() {
                    let mut chunk = [0; 64];
                    let count = chunk.len().min(bytes.len() - actual.len());
                    assert!(request.read(actual.len(), &mut chunk[..count], &inline, &mut stage));
                    actual.extend_from_slice(&chunk[..count]);
                }
                assert_eq!(actual, bytes);
                assert_eq!(stage.prepare, usize::from(body > 279));
                request.reset(&mut stage);
                assert!(!stage.held);
                assert_eq!(stage.closes, usize::from(body > 279));
                assert!(stage.data.iter().all(|byte| *byte == 0));
            }
        }
    }
}
#[test]
fn case2e_never_stages_and_non_fido_over279_drains_without_borrowing_pke() {
    for le in [1u16, 256, 65535, 0] {
        let mut bytes = vec![0, 0xca, 0, 0, 0];
        bytes.extend_from_slice(&le.to_be_bytes());
        let mut request = Request::new();
        let mut inline = [0; apdu::SHORT_FRAME_BYTES];
        let mut stage = Stage::default();
        for byte in &bytes {
            request.append(&[*byte], &mut inline, &mut stage);
        }
        assert_eq!(request.finish(&mut stage), Ok(()));
        assert_eq!(stage.prepare, 0);
    }
    for body in [279, 280, 281, 282, 1024] {
        let bytes = envelope(0, body, None);
        let mut request = Request::new();
        let mut inline = [0; apdu::SHORT_FRAME_BYTES];
        let mut stage = Stage::default();
        for chunk in bytes.chunks(17) {
            request.append(chunk, &mut inline, &mut stage);
        }
        assert_eq!(request.len(), bytes.len());
        assert_eq!(
            request.finish(&mut stage),
            if body <= 279 {
                Ok(())
            } else {
                Err(Rejection::Status(Sw::WRONG_LENGTH))
            }
        );
        assert!(!stage.held);
        assert_eq!(stage.writes, 0);
        request.reset(&mut stage);
    }
}
#[test]
fn rejection_and_write_failure_drain_but_malformed_final_envelope_wins() {
    for rejection in [
        Some(Rejection::TooLarge),
        Some(Rejection::Status(Sw::FILE_NOT_FOUND)),
        None,
    ] {
        for trailer in [0, 1, 2, 3] {
            let mut bytes = envelope(0x80, 700, None);
            bytes.extend(std::iter::repeat_n(0, trailer));
            let mut request = Request::new();
            let mut inline = [0; apdu::SHORT_FRAME_BYTES];
            let mut stage = Stage {
                rejection,
                fail: rejection.is_none(),
                ..Stage::default()
            };
            for chunk in bytes.chunks(23) {
                request.append(chunk, &mut inline, &mut stage);
            }
            assert_eq!(request.len(), bytes.len());
            let expected = if trailer == 1 || trailer == 3 {
                Rejection::Status(Sw::WRONG_LENGTH)
            } else {
                rejection.unwrap_or(Rejection::Status(Sw::UNABLE_TO_PROCESS))
            };
            assert_eq!(request.finish(&mut stage), Err(expected));
            assert_eq!(request.is_malformed(), trailer == 1 || trailer == 3);
            request.reset(&mut stage);
            assert!(!request.is_malformed());
            assert!(!stage.held);
            assert_eq!(stage.closes, usize::from(rejection.is_none()));
        }
    }
}
#[test]
fn real_link_retransmission_never_writes_staged_payload_twice() {
    let bytes = envelope(0x80, 700, Some(0));
    let mut link = Link::new();
    let mut request = Request::new();
    let mut inline = [0; apdu::SHORT_FRAME_BYTES];
    let mut stage = Stage::default();
    let mut number = 0;
    for (index, chunk) in bytes.chunks(20).enumerate() {
        let last = (index + 1) * 20 >= bytes.len();
        let mut frame = vec![0x02 | number | if last { 0 } else { 0x10 }];
        frame.extend_from_slice(chunk);
        frame.extend_from_slice(&[0, 0]);
        let mut deliver = |offset, data: &[u8]| {
            assert_eq!(offset, request.len());
            request.append(data, &mut inline, &mut stage);
            Ok(())
        };
        let event = link.receive_with(&frame, &mut deliver).unwrap();
        if last {
            assert!(matches!(event, Event::Execute(n) if n == bytes.len()));
        } else {
            assert!(matches!(event, Event::Send(_)));
            let before = stage.writes;
            link.receive_with(&frame, |_, _| panic!("repeated I-block delivered twice"))
                .unwrap();
            assert_eq!(stage.writes, before);
        }
        number ^= 1;
    }
    assert_eq!(request.finish(&mut stage), Ok(()));
    request.reset(&mut stage);
    assert_eq!(stage.closes, 1);
}
