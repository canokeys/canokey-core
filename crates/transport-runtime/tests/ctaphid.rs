// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE};
use canokey_transport_runtime::ctaphid::{
    Backend, Completion, Profile, Response, Session, TIMEOUT_MS,
};

const CID: u32 = 0x1234_5678;
const OTHER_CID: u32 = 0x8765_4321;
const INITIAL_PAYLOAD: usize = REPORT_SIZE - 7;
const CONTINUATION_PAYLOAD: usize = REPORT_SIZE - 5;
struct Permissive;
impl Profile for Permissive {
    const DEVICE_VERSION: [u8; 3] = [0x01, 0x02, 0x03];
    const CAPABILITIES: u8 = 0x05;
    const REGISTERED_CHANNELS: bool = false;
    const WRAP_CHANNELS: bool = false;
    const INCLUSIVE_TIMEOUT: bool = false;
    const CANCEL_DURING_RECEIVE: bool = false;
}
struct Registered;
impl Profile for Registered {
    const DEVICE_VERSION: [u8; 3] = Permissive::DEVICE_VERSION;
    const CAPABILITIES: u8 = Permissive::CAPABILITIES;
    const REGISTERED_CHANNELS: bool = true;
    const WRAP_CHANNELS: bool = true;
    const INCLUSIVE_TIMEOUT: bool = true;
    const CANCEL_DURING_RECEIVE: bool = true;
}
#[derive(Default)]
struct Fake {
    input: Vec<u8>,
    reads: Vec<(usize, usize)>,
    aborts: Vec<bool>,
    completions: Vec<u32>,
    begun: usize,
    resets: usize,
    resyncs: usize,
    busy: bool,
    fail_write: bool,
    fail_read: bool,
    response_length: Option<usize>,
}
impl Backend for Fake {
    fn reset(&mut self) {
        self.resets += 1;
        self.input.clear();
    }
    fn resynchronize(&mut self) {
        self.resyncs += 1;
    }
    fn begin(&mut self, _: u8, length: usize, _: u32) -> Result<(), Error> {
        if self.busy {
            return Err(Error::Busy);
        }
        if length > wire::MAX_MESSAGE {
            return Err(Error::Length);
        }
        self.begun += 1;
        self.input.clear();
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.fail_write {
            return Err(Error::Other);
        }
        assert_eq!(offset, self.input.len());
        self.input.extend_from_slice(bytes);
        Ok(())
    }
    fn finish(&mut self, _: u8, length: usize, _: u32) -> Result<usize, Error> {
        assert_eq!(length, self.input.len());
        Ok(self.response_length.unwrap_or(length))
    }
}
impl Response for Fake {
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        if self.fail_read {
            return Err(Error::Other);
        }
        self.reads.push((offset, out.len()));
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.input.get(offset + index).copied().unwrap_or(0xA5);
        }
        Ok(())
    }
    fn abort(&mut self, receiving: bool) {
        self.aborts.push(receiving);
    }
}
impl Completion for Fake {
    fn complete(&mut self, cid: u32) {
        self.completions.push(cid);
    }
}
fn initial(cid: u32, command: u8, length: usize, bytes: &[u8]) -> [u8; REPORT_SIZE] {
    let mut report = [0x00; REPORT_SIZE];
    let payload = wire::header(&mut report, cid, command, length);
    let count = bytes.len().min(payload.len());
    payload[..count].copy_from_slice(&bytes[..count]);
    report
}
fn continuation(cid: u32, sequence: u8, bytes: &[u8]) -> [u8; REPORT_SIZE] {
    let mut report = [0x00; REPORT_SIZE];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = sequence;
    let count = bytes.len().min(CONTINUATION_PAYLOAD);
    report[5..5 + count].copy_from_slice(&bytes[..count]);
    report
}
fn error(report: &[u8; REPORT_SIZE], cid: u32, status: Error) {
    assert_eq!(&report[..4], &cid.to_be_bytes());
    assert_eq!(&report[4..8], &[wire::ERROR, 0x00, 0x01, status as u8]);
}
#[test]
fn all_report_boundaries_preserve_input_and_wait_for_final_acknowledgement() {
    for length in [
        0,
        1,
        INITIAL_PAYLOAD,
        INITIAL_PAYLOAD + 1,
        192,
        193,
        2048,
        wire::MAX_MESSAGE,
    ] {
        let mut session = Session::<Permissive>::new();
        let mut backend = Fake::default();
        let body: Vec<u8> = (0..length).map(|n| n.wrapping_mul(37) as u8).collect();
        let mut output = [0x00; REPORT_SIZE];
        assert!(!session.receive(
            &initial(CID, wire::PING, length, &body),
            0,
            &mut output,
            &mut backend
        ));
        for (sequence, bytes) in body[INITIAL_PAYLOAD.min(length)..]
            .chunks(CONTINUATION_PAYLOAD)
            .enumerate()
        {
            assert!(!session.receive(
                &continuation(CID, sequence as u8, bytes),
                sequence as u32 + 1,
                &mut output,
                &mut backend
            ));
        }
        assert_eq!(backend.input, body);
        let mut echoed = Vec::new();
        let mut reports = 0;
        while session.transmit(&mut output, &mut backend) {
            let start = if reports == 0 {
                assert_eq!(output[4], wire::PING);
                assert_eq!(u16::from_be_bytes([output[5], output[6]]) as usize, length);
                7
            } else {
                assert_eq!(output[4], (reports - 1) as u8);
                5
            };
            let count = (length - echoed.len()).min(REPORT_SIZE - start);
            echoed.extend_from_slice(&output[start..start + count]);
            assert!(backend.completions.is_empty());
            assert!(session.active());
            reports += 1;
        }
        assert_eq!(echoed, body);
        assert_eq!(
            backend.reads.iter().map(|(_, count)| count).sum::<usize>(),
            length
        );
        session.completed(&mut backend);
        session.completed(&mut backend);
        assert_eq!(backend.completions, [CID]);
        assert!(backend.aborts.is_empty());
        assert!(!session.active());
    }
}
#[test]
fn contention_and_sequence_errors_do_not_execute_foreign_input() {
    let mut session = Session::<Permissive>::new();
    let mut backend = Fake::default();
    let mut out = [0x00; REPORT_SIZE];
    let start = initial(
        CID,
        wire::PING,
        INITIAL_PAYLOAD + 1,
        &[0xA5; INITIAL_PAYLOAD],
    );
    assert!(!session.receive(&start, 0, &mut out, &mut backend));
    assert!(session.receive(
        &initial(OTHER_CID, wire::PING, 0, &[]),
        1,
        &mut out,
        &mut backend
    ));
    error(&out, OTHER_CID, Error::Busy);
    assert_eq!(backend.begun, 1);
    assert!(backend.aborts.is_empty());
    assert!(session.receive(&continuation(CID, 0x01, &[0x5A]), 2, &mut out, &mut backend));
    error(&out, CID, Error::Sequence);
    assert_eq!(backend.aborts, [true]);
    assert!(!session.active());
}
#[test]
fn timeout_uses_packet_time_and_wraps_for_both_boundary_policies() {
    fn run<P: Profile>(inclusive: bool) {
        let mut session = Session::<P>::new();
        let mut backend = Fake::default();
        let mut out = [0x00; REPORT_SIZE];
        // Registered profiles first allocate CID 1 through broadcast INIT.
        assert!(session.receive(
            &initial(wire::BROADCAST, wire::INIT, 8, &[0x01; 8]),
            0,
            &mut out,
            &mut backend
        ));
        let cid = 0x0000_0001;
        let tick = u32::MAX - 99;
        assert!(!session.receive(
            &initial(
                cid,
                wire::PING,
                INITIAL_PAYLOAD + 1,
                &[0x01; INITIAL_PAYLOAD]
            ),
            tick,
            &mut out,
            &mut backend
        ));
        let boundary = tick.wrapping_add(TIMEOUT_MS);
        assert!(!session.timeout(boundary.wrapping_sub(1), &mut out, &mut backend));
        assert_eq!(session.timeout(boundary, &mut out, &mut backend), inclusive);
        if !inclusive {
            assert!(session.timeout(boundary.wrapping_add(1), &mut out, &mut backend));
        }
        error(&out, cid, Error::Timeout);
        assert_eq!(backend.aborts, [true]);
    }
    run::<Permissive>(false);
    run::<Registered>(true);
}
#[test]
fn init_preserves_nonce_and_rejects_unregistered_channels_before_backend_entry() {
    let mut session = Session::<Registered>::new();
    let mut backend = Fake::default();
    let mut out = [0x00; REPORT_SIZE];
    assert!(session.receive(&initial(CID, wire::PING, 0, &[]), 0, &mut out, &mut backend));
    error(&out, CID, Error::Channel);
    assert_eq!(backend.begun, 0);
    let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    assert!(session.receive(
        &initial(wire::BROADCAST, wire::INIT, nonce.len(), &nonce),
        1,
        &mut out,
        &mut backend
    ));
    assert_eq!(&out[7..15], &nonce);
    assert_eq!(
        &out[15..24],
        &[0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02, 0x03, 0x05]
    );
    assert!(session.receive(
        &initial(0x0000_0001, wire::INIT, nonce.len(), &nonce),
        2,
        &mut out,
        &mut backend
    ));
    assert_eq!(backend.resyncs, 1);
}
#[test]
fn failed_admission_preserves_owner_and_io_failures_abort_only_once() {
    let mut session = Session::<Permissive>::new();
    let mut backend = Fake {
        busy: true,
        ..Fake::default()
    };
    let mut out = [0x00; REPORT_SIZE];
    let request = initial(CID, wire::PING, 1, &[0x01]);
    assert!(session.receive(&request, 0, &mut out, &mut backend));
    error(&out, CID, Error::Busy);
    assert!(backend.aborts.is_empty());
    backend.busy = false;
    backend.fail_write = true;
    assert!(session.receive(&request, 1, &mut out, &mut backend));
    assert_eq!(backend.aborts, [true]);
    backend.fail_write = false;
    assert!(!session.receive(&request, 2, &mut out, &mut backend));
    backend.fail_read = true;
    assert!(session.transmit(&mut out, &mut backend));
    error(&out, CID, Error::Other);
    assert_eq!(backend.aborts, [true, false]);
    session.completed(&mut backend);
    assert!(!session.transmit(&mut out, &mut backend));
    assert!(backend.completions.is_empty());
}
#[test]
fn oversized_responses_never_reach_endpoint_and_cancel_produces_no_response() {
    for length in [wire::MAX_MESSAGE + 1, 65536, usize::MAX] {
        let mut session = Session::<Permissive>::new();
        let mut backend = Fake {
            response_length: Some(length),
            ..Fake::default()
        };
        let mut out = [0x00; REPORT_SIZE];
        assert!(session.receive(
            &initial(CID, wire::CBOR, 1, &[0x04]),
            0,
            &mut out,
            &mut backend
        ));
        error(&out, CID, Error::Length);
        assert!(backend.reads.is_empty());
        assert!(!session.transmit(&mut out, &mut backend));
        assert_eq!(backend.aborts, [true]);
    }
    let mut session = Session::<Permissive>::new();
    let mut backend = Fake::default();
    let mut out = [0xA5; REPORT_SIZE];
    assert!(!session.receive(
        &initial(CID, wire::CANCEL, 0, &[]),
        0,
        &mut out,
        &mut backend
    ));
    assert!(!session.active());
    assert!(!session.transmit(&mut out, &mut backend));
    assert!(backend.reads.is_empty());
}
