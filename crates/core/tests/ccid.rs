// SPDX-License-Identifier: Apache-2.0
//! C 3.1.2 short-only contract through the production CCID state machine.
use canokey_protocol::ccid::*;
use canokey_rust_core::runtime::ccid::{Backend, CONTROL_REPLY, REPLY, Request, Transport};
#[derive(Default)]
struct Mock {
    resets: usize,
    power_cycles: usize,
    executions: usize,
    input: Vec<u8>,
    arms: usize,
    disarms: usize,
    fail: bool,
    refuse_power: bool,
}
impl Backend for Mock {
    fn reset(&mut self) {
        self.resets += 1;
    }
    fn slot_power(&mut self) -> bool {
        if self.refuse_power {
            return false;
        }
        self.power_cycles += 1;
        true
    }
    fn exchange(&mut self, request: &Request, out: &mut [u8]) -> Result<usize, ()> {
        self.executions += 1;
        self.input = request.short().to_vec();
        if self.fail {
            return Err(());
        }
        out[..2].copy_from_slice(&[0x90, 0]);
        Ok(2)
    }
    fn arm(&mut self, bytes: &[u8; 10], interval: u16) {
        assert_eq!(interval, 500);
        assert_eq!(bytes[7..9], [0x80, 1]);
        self.arms += 1;
    }
    fn disarm(&mut self) {
        self.disarms += 1;
    }
}
fn frame(command: u8, bytes: &[u8]) -> Vec<u8> {
    let mut frame = vec![command, 0, 0, 0, 0, 0, 0x37, 0, 0, 0];
    frame[1..5].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
    frame
}
fn finish(t: &mut Transport, m: &mut Mock, hid_busy: bool) -> Vec<u8> {
    let mut output = [0; HEADER + REPLY];
    t.execute(hid_busy, m, &mut output);
    let reply = t.reply(&output).expect("complete declared RX").to_vec();
    t.submitted();
    t.completed();
    reply
}
fn start() -> (Transport, Mock) {
    let (mut t, mut m) = (Transport::new(), Mock::default());
    t.receive(&frame(POWER_ON, &[]));
    assert_eq!(&finish(&mut t, &mut m, false)[HEADER..], ATR);
    (t, m)
}
#[test]
fn foreign_refusal_drains_and_stays_latched_when_admission_changes() {
    let (mut t, mut m) = start();
    let wire = frame(TRANSFER, &[0x5a; 120]);
    t.receive_admitted(&wire[..64], false);
    assert!(!t.queued());
    t.receive_admitted(&wire[64..], true);
    assert!(!t.needs_apdu_buffer());
    let mut output = [0; CONTROL_REPLY];
    t.execute(false, &mut m, &mut output);
    let reply = t.reply(&output).unwrap();
    assert_eq!(&reply[HEADER..], &[0x64, 0]);
    assert_eq!(reply[7..9], [0, SUCCESS_ERROR]);
    assert_eq!((m.executions, m.arms, m.power_cycles), (0, 0, 1));
    t.submitted();
    t.completed();
    t.receive(&frame(TRANSFER, &[0, 3, 0, 0, 0]));
    assert_eq!(&finish(&mut t, &mut m, false)[HEADER..], &[0x90, 0]);
    assert_eq!(m.executions, 1);
}
#[test]
fn foreign_refusal_keeps_slot_and_length_error_precedence() {
    for (length, slot, error) in [(262, 0, BAD_LENGTH), (262, 1, BAD_SLOT), (5, 1, BAD_SLOT)] {
        let (mut t, mut m) = start();
        let mut wire = frame(TRANSFER, &vec![0; length]);
        wire[SLOT_OFFSET] = slot;
        for packet in wire.chunks(64) {
            t.receive_admitted(packet, false);
        }
        let mut output = [0; CONTROL_REPLY];
        t.execute(false, &mut m, &mut output);
        let reply = t.reply(&output).unwrap();
        assert_eq!(reply.len(), HEADER);
        assert_eq!(reply[8], error);
        assert_eq!((m.executions, m.arms), (0, 0));
    }
}
#[test]
fn refused_power_reset_preserves_active_slot_without_calling_reset() {
    let (mut t, mut m) = start();
    m.refuse_power = true;
    for command in [POWER_ON, POWER_OFF] {
        t.receive(&frame(command, &[]));
        let reply = finish(&mut t, &mut m, false);
        assert_eq!(reply[7..9], [COMMAND_FAILED, SLOT_BUSY]);
    }
    assert_eq!((m.power_cycles, m.resets), (1, 0));
    t.receive(&frame(SLOT_STATUS, &[]));
    assert_eq!(finish(&mut t, &mut m, false)[7..9], [0, SUCCESS_ERROR]);
}
#[test]
fn short261_every_split_and_packet_boundary() {
    let mut apdu = vec![0x80, 0x10, 0, 0, 255];
    apdu.resize(260, 0x5a);
    apdu.push(0);
    let wire = frame(TRANSFER, &apdu);
    assert_eq!(wire.len(), 271);
    for split in core::iter::once(0).chain(HEADER..=wire.len()) {
        let (mut t, mut m) = start();
        t.receive(&wire[..split]);
        t.receive(&wire[split..]);
        let reply = finish(&mut t, &mut m, false);
        assert_eq!(&reply[HEADER..], &[0x90, 0]);
        assert_eq!(m.input, apdu);
        assert_eq!((m.arms, m.disarms), (1, 1));
    }
    for size in [1, 10, 16, 63, 64] {
        let (mut t, mut m) = start();
        t.receive(&wire[..HEADER]);
        for piece in wire[HEADER..].chunks(size) {
            t.receive(piece);
        }
        assert_eq!(&finish(&mut t, &mut m, false)[HEADER..], &[0x90, 0]);
    }
}
#[test]
fn truncated_first_header_is_discarded_before_independent_message() {
    for length in 1..HEADER {
        let (mut t, mut m) = (Transport::new(), Mock::default());
        t.receive(&frame(POWER_ON, &[])[..length]);
        assert!(t.completed_transaction());
        t.receive(&frame(POWER_ON, &[]));
        let reply = finish(&mut t, &mut m, false);
        assert_eq!(&reply[HEADER..], ATR);
        assert_eq!((reply[7], reply[8]), (0, SUCCESS_ERROR));
        assert_eq!(m.power_cycles, 1);
    }
}
#[test]
fn atr_checksum_and_historical_bytes_match_the_card_contract() {
    assert_eq!(&ATR[9..16], b"Canokey");
    // ISO7816 TCK covers T0 through TCK, excluding the initial convention TS.
    assert_eq!(ATR[1..].iter().fold(0, |xor, byte| xor ^ byte), 0);
}
#[test]
fn bounded_extended_and_malformed_return6700_without_entering_core() {
    for apdu in [
        vec![],
        vec![0; 3],
        vec![0x80, 0x10, 0, 0, 0, 0, 1],
        vec![0x80, 0x10, 0, 0, 0, 0, 1, 4],
        vec![0x80, 0x10, 0, 0, 0, 0, 1, 4, 0, 0],
    ] {
        let (mut t, mut m) = start();
        t.receive(&frame(TRANSFER, &apdu));
        let reply = finish(&mut t, &mut m, false);
        assert_eq!(&reply[HEADER..], &[0x67, 0]);
        assert_eq!(reply[7..9], [0, SUCCESS_ERROR]);
        assert_eq!((m.executions, m.arms), (0, 0));
    }
}
#[test]
fn oversized_and_slot_payloads_drain_fully_before_one_reply_and_recover() {
    for command in [
        TRANSFER,
        POWER_ON,
        POWER_OFF,
        SLOT_STATUS,
        GET_PARAMETERS,
        0x69,
        0x6b,
        0x73,
    ] {
        for length in [262, 291, 1033, 4096] {
            let (mut t, mut m) = start();
            let wire = frame(command, &vec![0x5a; length]);
            let mut output = [0; HEADER + REPLY];
            for chunk in wire[..wire.len() - 1].chunks(64) {
                t.receive(chunk);
                // There is no receive clock/deadline to expire between chunks.
                t.execute(false, &mut m, &mut output);
                assert!(t.reply(&output).is_none());
            }
            t.receive(&wire[wire.len() - 1..]);
            let reply = finish(&mut t, &mut m, false);
            assert_eq!(reply.len(), HEADER);
            assert_eq!(
                reply[8],
                if [TRANSFER, POWER_ON, POWER_OFF, SLOT_STATUS, GET_PARAMETERS].contains(&command) {
                    1
                } else {
                    0
                }
            );
            assert_eq!(reply[7], 0x40);
            assert_eq!(m.executions, 0);
            t.receive(&frame(TRANSFER, &[0, 3, 0, 0, 0]));
            assert_eq!(&finish(&mut t, &mut m, false)[HEADER..], &[0x90, 0]);
        }
    }
    // Full 32-bit dwLength cannot wrap through the CCID header addition.
    let (mut t, mut m) = start();
    t.receive(&[0x6f, 255, 255, 255, 255, 0, 0, 0, 0, 0]);
    t.receive(&[0x5a; 64]);
    assert!(!t.queued());
    t.reset(&mut m);
    t.receive(&frame(POWER_ON, &[]));
    assert_eq!(&finish(&mut t, &mut m, false)[HEADER..], ATR);
}
#[test]
fn literal_response_families_slot_rfu_and_error_precedence() {
    // command, slot, response family, payload length, status, error, protocol.
    for [command, slot, kind, length, status, error, specific] in [
        [0x62, 0, 0x80, 17, 0, 0x81, 0],
        [0x63, 0, 0x81, 0, 1, 0x81, 0],
        [0x65, 0, 0x81, 0, 1, 0x81, 0],
        [0x6c, 0, 0x82, 7, 1, 0x81, 1],
        [0x6d, 0, 0x82, 0, 0x41, 0, 1],
        [0x61, 0, 0x82, 0, 0x41, 0, 1],
        [0x6b, 0, 0x83, 0, 0x41, 0, 0],
        [0x69, 0, 0x80, 0, 0x41, 0, 0],
        [0x73, 0, 0x84, 0, 0x41, 0, 0],
        [0x65, 1, 0x81, 0, 0x42, 5, 0],
        [0x6c, 1, 0x82, 0, 0x42, 5, 1],
        [0x62, 1, 0x80, 0, 0x42, 5, 0],
    ] {
        let (mut t, mut m) = (Transport::new(), Mock::default());
        t.receive(&[command, 0, 0, 0, 0, slot, 0x37, 0, 0, 0]);
        let reply = finish(&mut t, &mut m, false);
        assert_eq!(
            &reply[..10],
            &[kind, length, 0, 0, 0, slot, 0x37, status, error, specific]
        );
    }
    for command in [POWER_ON, POWER_OFF, SLOT_STATUS, GET_PARAMETERS] {
        for slot in [0, 1] {
            for length in [0, 1] {
                for reserved in [0, 1] {
                    let (mut t, mut m) = start();
                    let mut wire = frame(command, &vec![0; length]);
                    wire[5] = slot;
                    wire[8] = reserved;
                    t.receive(&wire);
                    let reply = finish(&mut t, &mut m, false);
                    let expected = if slot != 0 {
                        5
                    } else if length != 0 {
                        1
                    } else if reserved != 0 {
                        if command == POWER_ON { 8 } else { 7 }
                    } else {
                        SUCCESS_ERROR
                    };
                    assert_eq!(reply[8], expected);
                }
            }
        }
    }
}
#[test]
fn pending_in_is_immutable_and_busy_power_preserves_card_context() {
    let (mut t, mut m) = start();
    let cycles = m.power_cycles;
    t.receive(&frame(POWER_OFF, &[]));
    let reply = finish(&mut t, &mut m, true);
    assert_eq!(reply[7..9], [0x40, 0xe0]);
    assert_eq!(m.power_cycles, cycles);
    t.receive(&frame(SLOT_STATUS, &[]));
    assert_eq!(finish(&mut t, &mut m, false)[7], 0);
    t.receive(&frame(TRANSFER, &[0, 3, 0, 0, 0]));
    let mut output = [0; HEADER + REPLY];
    t.execute(false, &mut m, &mut output);
    let original = t.reply(&output).unwrap().to_vec();
    t.receive(&frame(POWER_OFF, &[]));
    assert_eq!(t.reply(&output).unwrap(), original);
    t.submitted();
    assert!(!t.can_receive());
    t.completed();
    assert!(t.can_receive());
}
