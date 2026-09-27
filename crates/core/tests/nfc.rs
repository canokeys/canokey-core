// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::nfc::{self, Block, Packet};
use canokey_rust_core::runtime::nfc::{Error, Event, Execution, Link};
#[test]
fn literal_wire_lengths_and_optional_fields() {
    assert_eq!(
        nfc::decode(&[0x12, 1, 2, 0, 0]),
        Ok(Block::Information {
            number: 0,
            chained: true,
            bytes: &[1, 2]
        })
    );
    assert_eq!(
        nfc::decode(&[0xb3, 0, 0]),
        Ok(Block::Receive {
            number: 1,
            negative: true
        })
    );
    assert_eq!(nfc::decode(&[0xf2, 1, 0, 0]), Ok(Block::Waiting(1)));
    assert_eq!(nfc::decode(&[0xc2, 0, 0]), Ok(Block::Deselect));
    for pcb in [0x00, 0x08, 0x0a, 0x06, 0xa0, 0xaa, 0xca, 0xff] {
        assert!(nfc::decode(&[pcb, 0, 0]).is_err());
    }
    for n in 0..=40 {
        if !(3..=32).contains(&n) {
            assert!(nfc::decode(&vec![2; n]).is_err());
        }
    }
    for multiplier in 0..=255 {
        assert_eq!(
            nfc::decode(&[0xf2, multiplier, 0, 0]).is_ok(),
            (1..=59).contains(&multiplier)
        );
    }
    assert_eq!(
        Packet::information(1, true, &[7, 8]).unwrap().bytes(),
        &[0x13, 7, 8]
    );
    assert_eq!(Packet::waiting(1).unwrap().bytes(), &[0xf2, 1]);
}
#[test]
fn chained_input_duplicates_are_not_appended_twice() {
    let mut l = Link::new();
    let mut input = [0; 261];
    assert_eq!(
        l.receive(&[0x12, 1, 2, 0, 0], &mut input),
        Ok(Event::Send(Packet::acknowledgement(0)))
    );
    assert_eq!(
        l.receive(&[0x12, 1, 2, 0, 0], &mut input),
        Ok(Event::Send(Packet::acknowledgement(0)))
    );
    assert_eq!(
        l.receive(&[0x03, 3, 4, 0, 0], &mut input),
        Ok(Event::Execute(4))
    );
    assert_eq!(&input[..4], &[1, 2, 3, 4]);
    assert_eq!(l.receive(&[0x03, 3, 4, 0, 0], &mut input), Err(Error::Busy));
    let p = l.response(&[0x90, 0], false).unwrap();
    assert_eq!(p.bytes(), &[3, 0x90, 0]);
    assert!(l.dirty());
    assert_eq!(l.sent(), Ok(2));
    assert!(!l.dirty());
    assert_eq!(
        l.receive(&[0x03, 3, 4, 0, 0], &mut input),
        Ok(Event::Send(p))
    );
    assert_eq!(l.receive(&[0xb3, 0, 0], &mut input), Ok(Event::Send(p)));
    assert_eq!(
        l.receive(&[0xa3, 0, 0], &mut input),
        Err(Error::Retransmits)
    );
}
#[test]
fn response_packet_commits_and_chaining_acknowledgements() {
    let mut l = Link::new();
    let mut input = [0; 261];
    assert_eq!(l.receive(&[2, 0, 0], &mut input), Ok(Event::Execute(0)));
    let bytes: Vec<u8> = (0..100).collect();
    let p = l.response(&bytes, false).unwrap();
    assert_eq!(p.bytes()[0], 0x12);
    assert_eq!(&p.bytes()[1..], &bytes[..29]);
    assert_eq!(l.receive(&[0xa3, 0, 0], &mut input), Err(Error::Busy));
    assert_eq!(l.sent(), Ok(29));
    assert_eq!(l.response(&bytes[29..], false), Err(Error::Busy));
    assert_eq!(l.receive(&[0xa2, 0, 0], &mut input), Ok(Event::Send(p)));
    assert_eq!(
        l.receive(&[0xa3, 0, 0], &mut input),
        Ok(Event::NextResponse)
    );
    let p = l.response(&bytes[29..58], true).unwrap();
    assert_eq!(p.bytes()[0], 0x13);
    assert_eq!(l.sent(), Ok(29));
    assert_eq!(
        l.receive(&[0xb2, 0, 0], &mut input),
        Ok(Event::NextResponse)
    );
    assert_eq!(
        l.response(&[0x90, 0], false).unwrap().bytes(),
        &[2, 0x90, 0]
    );
    l.sent().unwrap();
    assert_eq!(
        l.receive(&[0xb3, 0, 0], &mut input),
        Ok(Event::Send(Packet::acknowledgement(0)))
    );
    assert_eq!(l.receive(&[0xc2, 0, 0], &mut input), Ok(Event::Deselect));
    assert_eq!(l.receive(&[2, 7, 0, 0], &mut input), Ok(Event::Execute(1)));
}
#[test]
fn input_bounds_reject_without_changing_accepted_prefix() {
    let mut l = Link::new();
    let mut input = [0xaa; 261];
    for i in 0..9 {
        let mut frame = [0x55; 32];
        frame[0] = 0x12 | (i & 1);
        l.receive(&frame, &mut input).unwrap();
    }
    assert_eq!(l.receive(&[3, 1, 0, 0], &mut input), Err(Error::Overflow));
    assert!(input.iter().all(|&v| v == 0x55));
    l.reset();
    assert!(!l.dirty());
    assert_eq!(
        l.receive(&[2, 1, 2, 0, 0], &mut input[..1]),
        Err(Error::Overflow)
    );
    assert_eq!(l.receive(&[2, 1, 0, 0], &mut input), Ok(Event::Execute(1)));
}
#[test]
fn waiting_echo_wraparound_and_field_cancellation() {
    let mut e = Execution::new();
    assert!(!e.live());
    e.begin(u32::MAX - 99);
    assert!(!e.due(49));
    assert!(e.due(50));
    e.sent(50);
    assert!(!e.due(1000));
    assert!(!e.can_reply());
    assert_eq!(e.finish(), None);
    assert!(!e.echo(2));
    assert!(e.echo(1));
    assert!(e.can_reply());
    assert!(e.due(200));
    e.cancel();
    assert!(!e.live());
    assert!(!e.echo(1));
    assert_eq!(e.finish(), Some(false));
    e.begin(300);
    assert_eq!(e.finish(), Some(true));
    assert!(!e.live());
}

#[test]
fn recovery_preserves_clean_activation_and_does_not_timeout_crypto() {
    use canokey_rust_core::runtime::nfc::{HardwareAction, Recovery};
    let mut r = Recovery::new(0);
    let config = r.poll(0, false, false).unwrap();
    assert_eq!(config.operation, HardwareAction::ConfigureInterrupts);
    assert!(r.completed(config, false, 0));
    assert_eq!(r.poll(1, false, false), Some(config));
    assert!(r.completed(config, true, 1));
    assert_eq!(r.poll(200, false, false), None);
    assert_eq!(r.generation(), 0);
    assert_eq!(r.poll(1000, true, true), None);
    assert!(!r.drain_only());
    r.activity(1000);
    assert_eq!(r.poll(1199, true, false), None);
    let silence = r.poll(1200, true, false).unwrap();
    assert_eq!(silence.operation, HardwareAction::Silence);
    assert_eq!(r.generation(), 1);
    assert!(r.drain_only());
}
#[test]
fn forced_recovery_retries_and_cannot_be_cancelled_by_field_irqs() {
    use canokey_rust_core::runtime::nfc::{HardwareAction, Recovery};
    let mut r = Recovery::new(0);
    r.fault();
    let silence = r.poll(1, false, false).unwrap();
    assert!(r.completed(silence, false, 2));
    assert!(!r.activated(3));
    r.activity(4);
    assert_eq!(r.poll(5, false, false), Some(silence));
    r.fault();
    assert_eq!(r.generation(), 1);
    assert!(r.completed(silence, true, u32::MAX - 99));
    assert_eq!(r.poll(99, false, false), None);
    assert!(!r.activated(99));
    let unsilence = r.poll(100, false, false).unwrap();
    assert_eq!(unsilence.operation, HardwareAction::Unsilence);
    assert!(r.completed(unsilence, false, 101));
    assert!(r.drain_only());
    assert_eq!(r.poll(102, false, false), Some(unsilence));
    assert!(r.completed(unsilence, true, 103));
    assert!(!r.drain_only());
    let config = r.poll(104, false, false).unwrap();
    assert_eq!(config.operation, HardwareAction::ConfigureInterrupts);
    assert!(r.activated(105));
    assert!(!r.completed(config, true, 106));
    assert!(r.poll(106, false, false).is_some());
}
#[test]
fn irq_error_priority_matches_native_register_contract() {
    use canokey_rust_core::runtime::nfc::{Irq, irq};
    assert_eq!(
        irq([0x50, 0, 0]),
        Irq::Activity {
            activated: true,
            received: true
        }
    );
    assert_eq!(irq([0x50, 0, 4]), Irq::Halt);
    assert_eq!(irq([0x50, 4, 4]), Irq::Fault);
    for error in [8, 16, 32, 64] {
        assert_eq!(irq([0x50, 0, error | 4]), Irq::Fault);
    }
}

mod registers {
    use super::*;
    use canokey_rust_core::runtime::nfc_io::{Chip, Io};
    #[derive(Default)]
    struct Fake {
        flags: [u8; 3],
        rx: Vec<u8>,
        writes: Vec<(u16, Vec<u8>)>,
        fail: Option<u16>,
        reads: Vec<u16>,
    }
    impl Chip for Fake {
        fn read(&mut self, address: u16, out: &mut [u8]) -> bool {
            self.reads.push(address);
            if self.fail == Some(address) {
                return false;
            }
            match address {
                0xfff7 => out.copy_from_slice(&self.flags),
                0xfff2 => out[0] = self.rx.len() as u8,
                0xfff0 => out.copy_from_slice(&self.rx),
                _ => panic!("unexpected read"),
            }
            true
        }
        fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
            self.writes.push((address, bytes.to_vec()));
            self.fail != Some(address)
        }
    }
    fn frame(io: &mut Io, chip: &mut Fake, now: u32, bytes: &[u8]) {
        chip.flags = [0x10, 0, 0];
        chip.rx = bytes.to_vec();
        io.interrupt(now, chip);
    }
    #[test]
    fn wtx_uses_disjoint_mailbox_and_requires_echo_before_reply() {
        let mut io = Io::new(0);
        let mut chip = Fake::default();
        let mut packet = [0; 32];
        io.poll(0, false, &mut chip);
        assert_eq!(chip.writes, vec![(0xfffa, vec![0x22])]);
        frame(&mut io, &mut chip, 1, &[2, 1, 2, 0, 0]);
        assert_eq!(io.take(&mut packet), Some(5));
        assert!(io.begin_execution(1));
        io.tick(150, &mut chip);
        assert_eq!(chip.writes.len(), 1);
        io.tick(151, &mut chip);
        assert_eq!(
            &chip.writes[1..],
            &[(0xfff0, vec![0xf2, 1]), (0xfff4, vec![0x55])]
        );
        io.computed(152);
        assert_eq!(io.complete_execution(), None);
        frame(&mut io, &mut chip, 153, &[0xf2, 1, 0, 0]);
        assert_eq!(io.take(&mut packet), None);
        assert_eq!(io.complete_execution(), Some(true));
        assert!(io.send(
            &Packet::information(0, false, &[0x90, 0]).unwrap(),
            &mut chip
        ));
        let generation = io.generation();
        io.poll(1000, false, &mut chip);
        assert_eq!(io.generation(), generation);
    }
    #[test]
    fn field_reset_and_mailbox_overrun_revoke_old_execution() {
        let mut io = Io::new(0);
        let mut chip = Fake::default();
        let mut out = [0; 32];
        frame(&mut io, &mut chip, 1, &[2, 1, 0, 0]);
        io.take(&mut out);
        io.begin_execution(1);
        chip.flags = [0x40, 0, 0];
        io.interrupt(2, &mut chip);
        assert!(!io.live());
        assert_eq!(io.generation(), 1);
        io.computed(2);
        assert_eq!(io.complete_execution(), Some(false));
        frame(&mut io, &mut chip, 3, &[2, 7, 0, 0]);
        frame(&mut io, &mut chip, 4, &[3, 8, 0, 0]);
        assert_eq!(io.generation(), 2);
        assert_eq!(io.take(&mut out), None);
        io.poll(4, false, &mut chip);
        assert!(chip.writes.contains(&(0xffe6, vec![0x33])));
        chip.reads.clear();
        chip.flags = [0x50, 0, 0];
        io.interrupt(5, &mut chip);
        assert_eq!(chip.reads, vec![0xfff7]);
        assert_eq!(io.generation(), 2);
    }
    #[test]
    fn missing_wtx_echo_and_bus_failures_enter_rf_recovery() {
        let mut io = Io::new(0);
        let mut chip = Fake::default();
        let mut out = [0; 32];
        frame(&mut io, &mut chip, 0, &[2, 0, 0]);
        io.take(&mut out);
        io.begin_execution(0);
        io.tick(150, &mut chip);
        io.computed(151);
        io.poll(350, true, &mut chip);
        assert_eq!(io.generation(), 0);
        io.poll(351, true, &mut chip);
        assert_eq!(io.generation(), 1);
        assert!(!io.live());
        chip.fail = Some(0xffe6);
        io.poll(551, false, &mut chip);
        assert_eq!(chip.writes.last(), Some(&(0xffe6, vec![0xcc])));
        chip.fail = None;
        io.poll(552, false, &mut chip);
        io.poll(553, false, &mut chip);
        assert_eq!(chip.writes.last(), Some(&(0xfffa, vec![0x22])));
        frame(&mut io, &mut chip, 554, &[2, 0, 0]);
        io.take(&mut out);
        io.begin_execution(554);
        chip.fail = Some(0xfff4);
        io.tick(704, &mut chip);
        assert!(!io.live());
        assert_eq!(io.generation(), 2);
    }
}

mod provisioning {
    use canokey_rust_core::runtime::{
        nfc_io::Chip,
        nfc_provision::{Provision, configure},
    };
    struct Eeprom {
        bytes: [u8; 1024],
        selected: bool,
        writes: usize,
        accesses: usize,
        fail: Option<usize>,
        discard_write: bool,
    }
    impl Eeprom {
        fn new() -> Self {
            Self {
                bytes: [0xff; 1024],
                selected: false,
                writes: 0,
                accesses: 0,
                fail: None,
                discard_write: false,
            }
        }
        fn access(&mut self) -> bool {
            assert!(self.selected);
            let ok = self.fail != Some(self.accesses);
            self.accesses += 1;
            ok
        }
    }
    impl Chip for Eeprom {
        fn read(&mut self, address: u16, out: &mut [u8]) -> bool {
            if !self.access() {
                return false;
            }
            out.copy_from_slice(&self.bytes[address as usize..address as usize + out.len()]);
            true
        }
        fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
            if !self.access() {
                return false;
            }
            self.writes += 1;
            if !self.discard_write {
                self.bytes[address as usize..address as usize + bytes.len()].copy_from_slice(bytes);
            }
            true
        }
    }
    impl Provision for Eeprom {
        fn select(&mut self, active: bool) {
            self.selected = active;
        }
        fn delay_ms(&mut self, ms: u16) {
            assert!(self.selected && [1, 10].contains(&ms));
        }
    }
    #[test]
    fn config_is_verified_idempotent_and_releases_chip_on_every_bus_error() {
        let mut chip = Eeprom::new();
        assert!(configure(&mut chip));
        assert_eq!(chip.writes, 4);
        assert!(!chip.selected);
        let accesses = chip.accesses;
        assert_eq!(
            &chip.bytes[0x3b0..0x3b7],
            &[5, 0x72, 0xa0, 0x57, 0, 0x99, 0]
        );
        assert!(configure(&mut chip));
        assert_eq!(chip.writes, 4);
        for failure in 0..accesses {
            let mut chip = Eeprom::new();
            chip.fail = Some(failure);
            assert!(!configure(&mut chip));
            assert!(!chip.selected);
            chip.fail = None;
            assert!(configure(&mut chip)); // partially programmed EEPROM is recoverable
        }
        let mut chip = Eeprom::new();
        chip.discard_write = true;
        assert!(!configure(&mut chip));
        assert!(!chip.selected);
    }
}
