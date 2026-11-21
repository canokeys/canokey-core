// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::nfc as wire;
use canokey_transport_runtime::nfc::{Event, Link};
use canokey_transport_runtime::nfc_io::{Chip, Io, NoPolling};
use std::collections::VecDeque;

type Radio = Io<NoPolling, { wire::MAX_FRAME_BYTES }>;

struct Frontend {
    fifo: VecDeque<u8>,
    irq: [u8; wire::FM_IRQ_BYTES],
    status: u8,
    rats: u8,
    transmitted: Vec<u8>,
}

impl Frontend {
    fn new() -> Self {
        Self {
            fifo: VecDeque::new(),
            irq: [0x00; wire::FM_IRQ_BYTES],
            status: wire::FM_STATE_RATS << 4,
            rats: 0x80,
            transmitted: Vec::new(),
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
            wire::FM_REG_FIFO_ACCESS => self.push(bytes),
            wire::FM_REG_FIFO_CLEAR => self.fifo.clear(),
            wire::FM_REG_RF_TXEN => assert_eq!(bytes, &[wire::FM_RF_TX_ENABLE]),
            _ => panic!("unexpected register {address:#x}"),
        }
        true
    }
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
        let mut io = Radio::new(0);
        let mut chip = Frontend::new();
        let mut rx = vec![0x5a; length];
        rx[0] = wire::PCB_I_CHAIN;
        chip.receive(&mut io, &rx, aux);
        let mut frame = [0x00; wire::MAX_FRAME_BYTES];
        assert_eq!(io.take(&mut frame), valid.then_some(length));
        assert_eq!(io.generation(), u32::from(!valid));
        if valid {
            assert_eq!(&frame[..length], rx);
            let mut input = [0x00; wire::MAX_FRAME_BYTES];
            assert_eq!(
                Link::new().receive(&frame[..length], &mut input),
                Ok(Event::Send(wire::Packet::acknowledgement(0)))
            );
            assert_eq!(&input[..length - wire::FRAME_OVERHEAD], &rx[1..length - 2]);
        }
    }
}

#[test]
fn exact_tx_backing_and_retry_across_watermarks() {
    let mut chip = Frontend::new();
    let mut io = Radio::new(0);
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
    let mut io = Radio::new(0);
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
        let mut io = Radio::new(0);
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
    let mut io = Radio::new(0);
    chip.push(&[wire::PCB_I; wire::RX_WATERMARK]);
    chip.signal(&mut io, 0x00, wire::FM_FIFO_WATER, 0x00);
    chip.signal(&mut io, 0x00, 0x00, wire::FM_AUX_HALT);
    chip.receive(&mut io, &[wire::PCB_I, 0x00, 0x00], 0x00);
    let mut frame = [0x00; wire::MAX_FRAME_BYTES];
    assert_eq!(io.take(&mut frame), Some(3));
}

#[test]
fn reader_size_is_latched_only_after_rats_for_each_generation() {
    let mut io = Radio::new(0);
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
