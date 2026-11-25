// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::nfc as wire;
use canokey_transport_runtime::nfc::{Event, Link, RECOVERY_PERIOD};
use canokey_transport_runtime::nfc_io::{Chip, Io, NoPolling};
use std::collections::VecDeque;

type Radio<'a> = Io<'a, NoPolling, { wire::MAX_FRAME_BYTES }>;

struct Frontend {
    fifo: VecDeque<u8>,
    irq: [u8; wire::FM_IRQ_BYTES],
    status: u8,
    rats: u8,
    transmitted: Vec<u8>,
    reject_fifo_write: bool,
}

impl Frontend {
    fn new() -> Self {
        Self {
            fifo: VecDeque::new(),
            irq: [0x00; wire::FM_IRQ_BYTES],
            status: wire::FM_STATE_RATS << 4,
            rats: 0x80,
            transmitted: Vec::new(),
            reject_fifo_write: false,
        }
    }
    fn signal(&mut self, io: &mut Radio, main: u8, fifo: u8, aux: u8) {
        self.irq = [main, fifo, aux];
        io.interrupt(1, self);
        assert_eq!(self.irq, [0x00; wire::FM_IRQ_BYTES]);
    }
    fn push(&mut self, bytes: &[u8]) {
        assert!(self.fifo.len() + bytes.len() <= wire::FIFO_BYTES);
        self.fifo.extend(bytes);
    }
    fn receive(&mut self, io: &mut Radio, mut bytes: &[u8], aux: u8) {
        while bytes.len() > wire::FIFO_BYTES {
            self.push(&bytes[..wire::RX_WATERMARK]);
            bytes = &bytes[wire::RX_WATERMARK..];
            self.signal(io, 0x00, wire::FM_FIFO_WATER, 0x00);
            assert!(self.fifo.is_empty());
            assert_eq!(io.take(&mut [0x00; wire::MAX_FRAME_BYTES]), None);
        }
        self.push(bytes);
        let water = if bytes.len() >= wire::RX_WATERMARK {
            wire::FM_FIFO_WATER
        } else {
            0x00
        };
        self.signal(io, wire::FM_MAIN_RX_DONE, water, aux);
    }
    fn transmit(&mut self, io: &mut Radio) -> Vec<u8> {
        while self.fifo.len() > wire::TX_WATERMARK {
            let count = self.fifo.len() - wire::TX_WATERMARK;
            self.transmitted.extend(self.fifo.drain(..count));
            self.signal(io, 0x00, wire::FM_FIFO_WATER, 0x00);
            assert!(!io.take_tx_done());
        }
        self.transmitted.extend(self.fifo.drain(..));
        self.signal(io, wire::FM_MAIN_TX_DONE, wire::FM_FIFO_WATER, 0x00);
        std::mem::take(&mut self.transmitted)
    }
}

impl Chip for Frontend {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool {
        match address {
            wire::FM_REG_MAIN_IRQ => out.copy_from_slice(&std::mem::take(&mut self.irq)),
            wire::FM_REG_FIFO_WORDCNT => out[0] = self.fifo.len() as u8,
            wire::FM_REG_FIFO_ACCESS => {
                assert!(out.len() <= wire::FIFO_BYTES);
                for byte in out {
                    *byte = self.fifo.pop_front().expect("FIFO underflow");
                }
            }
            wire::FM_REG_RF_STATUS => out[0] = self.status,
            wire::FM_REG_RF_RATS => out[0] = self.rats,
            _ => panic!("unexpected register {address:#x}"),
        }
        true
    }
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
        match address {
            wire::FM_REG_FIFO_ACCESS => {
                if self.reject_fifo_write {
                    return false;
                }
                self.push(bytes);
            }
            wire::FM_REG_MAIN_IRQ_MASK | wire::FM_REG_RESET_SILENCE => {}
            wire::FM_REG_FIFO_CLEAR => self.fifo.clear(),
            wire::FM_REG_RF_TXEN => assert_eq!(bytes, &[wire::FM_RF_TX_ENABLE]),
            _ => panic!("unexpected register {address:#x}"),
        }
        true
    }
}

#[test]
fn idle_clock_requires_clean_link_fifo_and_recovery() {
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut chip = Frontend::new();
    assert!(!io.poll(0, false, &mut chip)); // initial IRQ mask write
    assert!(io.poll(1, false, &mut chip));
    assert!(!io.poll(1, true, &mut chip)); // outstanding link work
    chip.push(&[wire::PCB_I; wire::RX_WATERMARK]);
    chip.signal(&mut io, 0x00, wire::FM_FIFO_WATER, 0x00);
    assert!(!io.poll(1, false, &mut chip)); // partial FIFO frame
    chip.receive(&mut io, &[0x00, 0x00], 0x00);
    assert!(!io.poll(1, false, &mut chip)); // complete frame in mailbox
    io.take(&mut [0; wire::MAX_FRAME_BYTES]).unwrap();
    assert!(io.begin_execution(1));
    assert!(!io.poll(1, false, &mut chip)); // WTX timer owns the turn
    io.computed(2);
    assert_eq!(io.complete_execution(), Some(true));
    assert!(io.send(&wire::Packet::acknowledgement(0), &mut chip));
    assert!(!io.poll(2, false, &mut chip)); // TX still owns the FIFO
    chip.transmit(&mut io);
    assert!(io.poll(2, false, &mut chip));

    io.fault();
    assert!(!io.poll(3, false, &mut chip)); // silence request
    assert!(!io.poll(4, false, &mut chip)); // waiting to unsilence
    let resume = 3 + RECOVERY_PERIOD;
    assert!(!io.poll(resume, false, &mut chip)); // unsilence
    assert!(!io.poll(resume, false, &mut chip)); // configure IRQs
    assert!(io.poll(resume, false, &mut chip));
}

#[test]
fn receive_boundaries_and_crc_gate() {
    for (length, aux, valid) in [
        (24, 0x00, true),
        (32, 0x00, true),
        (255, 0x00, true),
        (256, 0x00, true),
        (257, 0x00, false),
        (256, 0x10, false), // CRC error
        (256, 0x08, false), // Frame error
    ] {
        let mut backing = [0; wire::MAX_FRAME_BYTES];
        let mut io = Radio::new(0, Some(&mut backing));
        let mut chip = Frontend::new();
        let mut rx = vec![0x5a; length];
        rx[0] = wire::PCB_I_CHAIN;
        chip.receive(&mut io, &rx, aux);
        let frame = io.take_frame();
        assert_eq!(
            frame.as_ref().map(|frame| frame.bytes().len()),
            valid.then_some(length)
        );
        assert_eq!(io.generation(), u32::from(!valid));
        if let Some(frame) = frame {
            assert_eq!(frame.bytes(), rx);
            let mut input = [0x00; wire::MAX_FRAME_BYTES];
            assert_eq!(
                Link::new().receive(frame.bytes(), &mut input),
                Ok(Event::Send(wire::Packet::acknowledgement(0)))
            );
            assert_eq!(&input[..length - wire::FRAME_OVERHEAD], &rx[1..length - 2]);
            assert!(io.return_frame(frame));
        }
    }
}

#[test]
fn exact_tx_backing_and_retry_across_watermarks() {
    let mut chip = Frontend::new();
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut link = Link::new();
    let mut frame = [0x00; wire::MAX_FRAME_BYTES];
    let mut input = [0x00; 1];
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    let n = io.take(&mut frame).unwrap();
    assert_eq!(link.receive(&frame[..n], &mut input), Ok(Event::Execute(0)));
    let backing: Vec<u8> = (0..=255).collect();
    let response = link
        .response(backing.len(), false, io.tx_frame_limit(256))
        .unwrap();
    assert_eq!(response.length, 253);
    let inf = &backing[..usize::from(response.length)];
    let mut staging = inf.to_vec();
    assert!(io.send_response(response, &staging, &mut chip));
    staging.fill(0x00);
    assert!(link.response_pending());
    assert!(!io.take_tx_done());
    let sent = chip.transmit(&mut io);
    assert_eq!(sent[0], wire::PCB_I_CHAIN);
    assert_eq!(&sent[1..], inf);
    assert!(io.take_tx_done());
    assert_eq!(link.sent(), Some(253));
    chip.receive(&mut io, &[wire::PCB_NAK, 0x00, 0x00], 0x00);
    let n = io.take(&mut frame).unwrap();
    assert_eq!(
        link.receive(&frame[..n], &mut input),
        Ok(Event::RetryResponse(response))
    );
    assert!(io.send_response(response, inf, &mut chip));
    assert_eq!(chip.transmit(&mut io), sent);
    assert!(io.take_tx_done());
    assert!(!link.response_pending());
    assert_eq!(io.generation(), 0);
}

#[test]
fn tx_watermark_refills_with_a_latched_empty_flag() {
    let mut chip = Frontend::new();
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    io.take(&mut [0x00; wire::MAX_FRAME_BYTES]).unwrap();
    let inf = [0x5a; wire::FIFO_BYTES];
    let response = canokey_transport_runtime::nfc::Response {
        pcb: wire::PCB_I,
        length: inf.len() as u8,
    };
    assert!(io.send_response(response, &inf, &mut chip));
    let consumed = wire::FIFO_BYTES - wire::TX_WATERMARK;
    chip.transmitted.extend(chip.fifo.drain(..consumed));
    chip.signal(
        &mut io,
        0x00,
        wire::FM_FIFO_WATER | wire::FM_FIFO_EMPTY,
        0x00,
    );
    assert_eq!(chip.fifo.len(), wire::TX_WATERMARK + 1);
    assert_eq!(io.generation(), 0);
    assert!(!io.take_tx_done());
    let sent = chip.transmit(&mut io);
    assert_eq!(sent[0], wire::PCB_I);
    assert_eq!(&sent[1..], inf);
    assert!(io.take_tx_done());
}

#[test]
fn faults_and_new_activation_cancel_partial_transfers() {
    for (main, fifo, aux) in [
        (0x00, wire::FM_FIFO_OVERFLOW, 0x00),
        (wire::FM_MAIN_TX_DONE, wire::FM_FIFO_WATER, 0x00),
        (0x00, 0x00, wire::FM_AUX_HALT),
        (wire::FM_MAIN_POWER_ON, 0x00, 0x00),
    ] {
        let mut chip = Frontend::new();
        let mut backing = [0; wire::MAX_FRAME_BYTES];
        let mut io = Radio::new(0, Some(&mut backing));
        chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
        io.take(&mut [0x00; wire::MAX_FRAME_BYTES]).unwrap();
        let response = canokey_transport_runtime::nfc::Response {
            pcb: wire::PCB_I,
            length: 64,
        };
        assert!(io.send_response(response, &[0x5a; 64], &mut chip));
        chip.signal(&mut io, main, fifo, aux);
        assert_eq!(io.generation(), 1);
        assert!(!io.take_tx_done());
        assert_eq!(io.tx_frame_limit(256), 0);
    }

    let mut chip = Frontend::new();
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    chip.push(&[wire::PCB_I; wire::RX_WATERMARK]);
    chip.signal(&mut io, 0x00, wire::FM_FIFO_WATER, 0x00);
    chip.signal(&mut io, 0x00, 0x00, wire::FM_AUX_HALT);
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    let mut frame = [0x00; wire::MAX_FRAME_BYTES];
    assert_eq!(io.take(&mut frame), Some(3));
}

#[test]
fn activation_revokes_loan_and_discards_frames_until_backing_returns() {
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut chip = Frontend::new();
    let rx = [wire::PCB_I, 0x5a, 0x00, 0x00];
    chip.receive(&mut io, &rx, 0x00);
    let frame = io.take_frame().unwrap();
    assert!(io.take_frame().is_none());
    chip.signal(&mut io, wire::FM_MAIN_ACTIVE, 0x00, 0x00);
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);

    // Return the frame in the middle of another dropped frame. Its tail
    // must not become a new mailbox even though backing is available again.
    chip.push(&[0x5a; wire::RX_WATERMARK]);
    chip.signal(&mut io, 0x00, wire::FM_FIFO_WATER, 0x00);
    assert_eq!(frame.bytes(), rx);
    assert!(!io.return_frame(frame));
    chip.push(&[wire::PCB_I, 0x00, 0x00]);
    chip.signal(&mut io, wire::FM_MAIN_RX_DONE, 0x00, 0x00);
    assert!(io.take_frame().is_none());
    chip.receive(&mut io, &rx, 0x00);
    let frame = io.take_frame().unwrap();
    assert_eq!(frame.bytes(), rx);
    assert!(io.return_frame(frame));
    assert_eq!(io.generation(), 1);
}

#[test]
fn refill_failure_does_not_complete_or_advance_the_response() {
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut chip = Frontend::new();
    let mut link = Link::new();
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    let frame = io.take_frame().unwrap();
    assert_eq!(link.receive(frame.bytes(), &mut []), Ok(Event::Execute(0)));
    assert!(io.return_frame(frame));
    let inf = [0x5a; wire::FIFO_BYTES];
    let response = link
        .response(inf.len(), false, io.tx_frame_limit(256))
        .unwrap();
    assert!(io.send_response(response, &inf, &mut chip));
    chip.fifo.drain(..wire::RX_WATERMARK);
    chip.reject_fifo_write = true;
    chip.signal(&mut io, 0x00, wire::FM_FIFO_WATER, 0x00);
    chip.signal(&mut io, wire::FM_MAIN_TX_DONE, wire::FM_FIFO_WATER, 0x00);
    assert!(!io.take_tx_done());
    assert!(link.response_pending());
    assert_eq!(io.generation(), 1);
}

#[test]
fn tx_done_with_watermark_and_rx_done_preserves_the_next_block() {
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut chip = Frontend::new();
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    let frame = io.take_frame().unwrap();
    assert!(io.return_frame(frame));
    let response = canokey_transport_runtime::nfc::Response {
        pcb: wire::PCB_I_CHAIN,
        length: 1,
    };
    assert!(io.send_response(response, &[0x5a], &mut chip));
    chip.fifo.clear(); // The preceding response has left the FIFO.
    let ack = [wire::PCB_ACK_NEXT, 0x00, 0x00];
    chip.push(&ack);
    chip.signal(
        &mut io,
        wire::FM_MAIN_TX_DONE | wire::FM_MAIN_RX_DONE,
        wire::FM_FIFO_WATER,
        0x00,
    );
    assert!(io.take_tx_done());
    let frame = io.take_frame().unwrap();
    assert_eq!(frame.bytes(), ack);
    assert!(io.return_frame(frame));
    assert_eq!(io.generation(), 0);
}

#[test]
fn reader_size_is_latched_only_after_rats_for_each_generation() {
    let mut backing = [0; wire::MAX_FRAME_BYTES];
    let mut io = Radio::new(0, Some(&mut backing));
    let mut chip = Frontend::new();
    let mut frame = [0x00; wire::MAX_FRAME_BYTES];
    let sizes = [
        16, 24, 32, 40, 48, 64, 96, 128, 256, 16, 16, 16, 16, 16, 16, 16,
    ];
    for (fsdi, fsd) in sizes.into_iter().enumerate() {
        chip.status = 0x80; // Selected, before RATS.
        chip.signal(&mut io, wire::FM_MAIN_ACTIVE, 0x00, 0x00);
        assert_eq!(io.tx_frame_limit(256), 0);
        chip.rats = ((fsdi as u8) << 4) | 0x0a;
        chip.status = wire::FM_STATE_PPS << 4;
        chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
        assert_eq!(io.take(&mut frame), Some(3));
        assert_eq!(io.tx_frame_limit(256), fsd);
        assert_eq!(io.tx_frame_limit(32), fsd.min(32));
        let mut link = Link::new();
        link.receive(&frame[..3], &mut []).unwrap();
        assert_eq!(
            usize::from(link.response(260, false, fsd).unwrap().length) + wire::FRAME_OVERHEAD,
            fsd
        );
        assert_eq!(io.generation(), fsdi as u32 + 1);
    }
}
