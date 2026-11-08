// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::nfc::Packet;
use canokey_transport_runtime::nfc::{Error, Event, Link, MAX_RETRANSMITS};

#[test]
fn repeated_empty_and_nonempty_blocks_write_backing_once() {
    let mut link = Link::new();
    let mut accepted = Vec::new();
    let mut deliver = |offset: usize, bytes: &[u8]| {
        accepted.push((offset, bytes.to_vec()));
        Ok(())
    };
    // ISO-DEP I-blocks include two frontend-checked CRC bytes on receive.
    let empty_chained = [0x12, 0x00, 0x00];
    let data_chained = [0x13, 0x5a, 0x00, 0x00];
    let final_block = [0x02, 0xc3, 0x00, 0x00];
    for _ in 0..4 {
        assert_eq!(
            link.receive_with(&empty_chained, &mut deliver),
            Ok(Event::Send(Packet::acknowledgement(0)))
        );
    }
    for _ in 0..4 {
        assert_eq!(
            link.receive_with(&data_chained, &mut deliver),
            Ok(Event::Send(Packet::acknowledgement(1)))
        );
    }
    assert_eq!(
        link.receive_with(&final_block, &mut deliver),
        Ok(Event::Execute(2))
    );
    assert_eq!(
        link.receive_with(&final_block, &mut deliver),
        Err(Error::Busy)
    );
    assert_eq!(accepted, [(0, vec![]), (0, vec![0x5a]), (1, vec![0xc3])]);
}

#[test]
fn opposite_number_nak_never_advances_a_response_cursor() {
    let mut link = Link::new();
    let mut input = [];
    link.receive(&[0x02, 0x00, 0x00], &mut input).unwrap();
    let payload = [0x5a; 40];
    let first = link.response(&payload, false).unwrap();
    assert_eq!(link.sent(), Ok(29));
    // ISO-DEP R(NAK), opposite BN: emit a control ACK without consuming INF.
    let ack = Packet::acknowledgement(0);
    assert_eq!(
        link.receive(&[0xb3, 0x00, 0x00], &mut input),
        Ok(Event::Send(ack))
    );
    assert_eq!(link.number(), 0);
    assert_eq!(link.response(&payload[29..], false), Err(Error::Busy));
    // Matching BN repeats the last control reply, not the earlier data packet.
    assert_eq!(
        link.receive(&[0xb2, 0x00, 0x00], &mut input),
        Ok(Event::Send(ack))
    );
    assert_ne!(ack, first);
    assert_eq!(
        link.receive(&[0xa3, 0x00, 0x00], &mut input),
        Ok(Event::NextResponse)
    );
    let last = link.response(&payload[29..], false).unwrap();
    assert_eq!(&last.bytes()[1..], &payload[29..]);
    assert_eq!(link.sent(), Ok(11));
}

#[test]
fn polling_handoff_retransmits_exact_reply_then_admits_a_new_command() {
    let mut link = Link::new();
    let mut input = [0x00; 8];
    link.receive(&[0x02, 0x80, 0x00, 0x00], &mut input).unwrap();
    let initial = link.response(&[0x01, 0x91, 0x00], false).unwrap();
    link.sent().unwrap();
    let cancelled = Packet::information(1, false, &[0x2d, 0x90, 0x00]).unwrap();
    link.polled(1, cancelled);
    assert!(!link.dirty());
    assert_eq!(link.number(), 1);
    for _ in 0..MAX_RETRANSMITS {
        assert_eq!(
            link.receive(&[0xb3, 0x00, 0x00], &mut input),
            Ok(Event::Send(cancelled))
        );
    }
    assert_ne!(initial, cancelled);
    assert_eq!(
        link.receive(&[0xa3, 0x00, 0x00], &mut input),
        Err(Error::Retransmits)
    );
    assert_eq!(
        link.receive(&[0xa2, 0x00, 0x00], &mut input),
        Ok(Event::Ignored)
    );
    assert_eq!(
        link.receive(&[0x02, 0xa4, 0x00, 0x00], &mut input),
        Ok(Event::Execute(1))
    );
    assert_eq!(input[0], 0xa4);
}
