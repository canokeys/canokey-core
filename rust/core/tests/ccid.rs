// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::ccid::*;
use canokey_rust_core::runtime::ccid::{Backend, Request, Scratch, TIMEOUT, Transport};

struct Mock {
    now: u32,
    pke: [u8; 1024],
    held: bool,
    closes: usize,
    resets: usize,
    executions: usize,
    input: Vec<u8>,
    prepare_error: Option<u16>,
    acquire_fail: bool,
    write_fail: bool,
    read_fail: bool,
    exchange_fail: bool,
    arms: usize,
    disarms: usize,
    reply_size: usize,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            now: 0,
            pke: [0; 1024],
            held: false,
            closes: 0,
            resets: 0,
            executions: 0,
            input: vec![],
            prepare_error: None,
            acquire_fail: false,
            write_fail: false,
            read_fail: false,
            exchange_fail: false,
            arms: 0,
            disarms: 0,
            reply_size: 2,
        }
    }
}
impl Scratch for Mock {
    fn acquire(&mut self, n: usize) -> bool {
        assert!(!self.held);
        assert!(n <= 1024);
        if self.acquire_fail {
            return false;
        }
        self.held = true;
        true
    }
    fn write(&mut self, at: usize, bytes: &[u8]) -> bool {
        assert!(self.held);
        if self.write_fail {
            return false;
        }
        self.pke[at..at + bytes.len()].copy_from_slice(bytes);
        true
    }
    fn read(&mut self, at: usize, bytes: &mut [u8]) -> bool {
        assert!(self.held);
        if self.read_fail {
            return false;
        }
        bytes.copy_from_slice(&self.pke[at..at + bytes.len()]);
        true
    }
    fn close(&mut self) {
        assert!(self.held);
        self.pke.fill(0);
        self.held = false;
        self.closes += 1;
    }
}
impl Backend for Mock {
    fn now(&mut self) -> u32 {
        self.now
    }
    fn reset(&mut self) {
        assert!(!self.held);
        self.resets += 1;
    }
    fn prepare_extended(&mut self, prefix: &[u8; 7], total: usize) -> Result<u16, u16> {
        assert!(!self.held);
        if let Some(sw) = self.prepare_error {
            return Err(sw);
        }
        if prefix[..5] != [0x80, 0x10, 0, 0, 0] {
            return Err(0x6700);
        }
        let n = u16::from_be_bytes([prefix[5], prefix[6]]);
        if n == 0 || n > 1024 || ![7 + n as usize, 9 + n as usize].contains(&total) {
            return Err(0x6700);
        }
        Ok(n)
    }
    fn exchange(&mut self, request: &mut Request, out: &mut [u8]) -> Result<usize, ()> {
        self.input.clear();
        if request.staged() {
            let mut chunk = [0; 64];
            for offset in (0..request.len()).step_by(64) {
                let n = 64.min(request.len() - offset);
                if !request.read(offset, &mut chunk[..n], self) {
                    request.close(self);
                    return Err(());
                }
                self.input.extend_from_slice(&chunk[..n]);
            }
            assert!(!request.read(request.len(), &mut chunk[..1], self));
            request.close(self);
        } else {
            self.input.extend_from_slice(request.short());
        }
        assert!(!self.held); // Crypto may now overwrite PKE.
        self.pke.fill(0xa5);
        self.executions += 1;
        if self.exchange_fail {
            return Err(());
        }
        out[..self.reply_size].fill(0);
        out[0] = 0x90;
        Ok(self.reply_size)
    }
    fn arm(&mut self, bytes: &[u8; 10], interval: u16) {
        assert_eq!(bytes, &[0x80, 0, 0, 0, 0, 0, 0x56, 0x80, 1, 0]);
        assert_eq!(interval, 500);
        self.arms += 1;
    }
    fn disarm(&mut self) {
        self.disarms += 1;
    }
}
fn frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![command, 0, 0, 0, 0, 0, 0x56, 0, 0, 0];
    v[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    v
}
fn finish(t: &mut Transport, m: &mut Mock) -> Vec<u8> {
    let mut output = [0; HEADER + canokey_rust_core::runtime::ccid::REPLY];
    t.execute(false, m, &mut output);
    let r = t.reply(&output).unwrap().to_vec();
    t.submitted();
    t.completed();
    r
}
fn start() -> (Transport, Mock) {
    let mut t = Transport::new();
    let mut m = Mock::default();
    t.receive(&frame(POWER_ON, &[]), 0, true, &mut m);
    assert_eq!(&finish(&mut t, &mut m)[10..], ATR);
    (t, m)
}
fn extended(n: usize, le: bool) -> Vec<u8> {
    let mut bytes = vec![0x80, 0x10, 0, 0, 0, (n >> 8) as u8, n as u8];
    bytes.extend((0..n).map(|x| (x * 37) as u8));
    if le {
        bytes.extend([1, 0x23]);
    }
    frame(TRANSFER, &bytes)
}
#[test]
fn literal_header_and_all_short_splits() {
    let h = [0x6f, 0x2c, 1, 0, 0, 0, 0x56, 0, 0, 0];
    assert_eq!(payload_length(&h), 300);
    for split in 0..=15 {
        let (mut t, mut m) = start();
        let f = frame(TRANSFER, &[0, 0xc0, 0, 0, 0]);
        t.receive(&f[..split], 0, true, &mut m);
        t.receive(&f[split..], 0, true, &mut m);
        assert_eq!(
            finish(&mut t, &mut m),
            [0x80, 2, 0, 0, 0, 0, 0x56, 0, 0, 0, 0x90, 0]
        );
        assert_eq!(m.input, [0, 0xc0, 0, 0, 0]);
        assert_eq!(m.arms, 1);
        assert_eq!(m.disarms, 1);
    }
}
#[test]
fn extended_every_split_and_packet_boundary() {
    for n in [253, 254, 291, 1024] {
        for le in [false, true] {
            let f = extended(n, le);
            for split in 1..f.len() {
                let (mut t, mut m) = start();
                for piece in f[..split].chunks(64) {
                    t.receive(piece, 0, true, &mut m);
                }
                for piece in f[split..].chunks(64) {
                    t.receive(piece, 0, true, &mut m);
                }
                let r = finish(&mut t, &mut m);
                assert_eq!(r[7..9], [0, 0]);
                assert_eq!(m.input, f[10..]);
                assert!(!m.held);
                assert_eq!(m.closes, usize::from(f.len() > 271));
            }
        }
    }
}
#[test]
fn every_truncated_header_and_payload_expires() {
    let f = extended(291, true);
    for end in 1..f.len() {
        let (mut t, mut m) = start();
        m.now = u32::MAX - 100;
        for piece in f[..end].chunks(64) {
            t.receive(piece, m.now, true, &mut m);
        }
        t.timeout(m.now.wrapping_add(TIMEOUT - 1), &mut m);
        assert!(!t.queued());
        t.timeout(m.now.wrapping_add(TIMEOUT), &mut m);
        if end >= 10 {
            assert_eq!(finish(&mut t, &mut m)[7..9], [0x40, 8]);
        } else {
            assert!(t.can_receive());
        }
        assert!(!m.held);
        assert_eq!(m.executions, 0);
    }
}
#[test]
fn late_queued_packet_does_not_revive_input() {
    let (mut t, mut m) = start();
    let f = extended(291, true);
    t.receive(&f[..64], 0, true, &mut m);
    t.receive(&f[64..128], 2000, true, &mut m);
    assert_eq!(finish(&mut t, &mut m)[8], BAD_LENGTH);
    assert_eq!(m.closes, 1);
    assert_eq!(m.executions, 0);
}
#[test]
fn errors_and_cleanup_before_execution() {
    for fault in 0..6 {
        let (mut t, mut m) = start();
        match fault {
            0 => m.prepare_error = Some(0x6986),
            1 => m.acquire_fail = true,
            2 => m.write_fail = true,
            3 => m.read_fail = true,
            4 => m.exchange_fail = true,
            _ => (),
        }
        let f = extended(291, true);
        for p in f.chunks(64) {
            t.receive(p, 0, true, &mut m);
        }
        let r = finish(&mut t, &mut m);
        if fault == 0 {
            assert_eq!(&r[10..], &[0x69, 0x86]);
        } else if fault < 5 {
            assert_eq!(r[8], HARDWARE);
        }
        assert!(!m.held);
        assert_eq!(m.closes, usize::from(fault >= 2));
    }
}
#[test]
fn reset_closes_once_and_does_not_execute_partial() {
    let (mut t, mut m) = start();
    let f = extended(291, true);
    t.receive(&f[..64], 0, true, &mut m);
    assert!(t.scratch_busy());
    t.reset(&mut m);
    t.reset(&mut m);
    assert_eq!(m.closes, 1);
    assert_eq!(m.executions, 0);
    assert!(t.can_receive());
}
#[test]
fn overflow_oversized_and_trailing_bytes_are_rejected() {
    for n in [1034, u32::MAX - 9, u32::MAX] {
        let (mut t, mut m) = start();
        let mut f = frame(TRANSFER, &[]);
        f[1..5].copy_from_slice(&n.to_le_bytes());
        t.receive(&f, 0, true, &mut m);
        t.timeout(2000, &mut m);
        assert_eq!(finish(&mut t, &mut m)[8], BAD_LENGTH);
        assert_eq!(m.executions, 0);
    }
    let (mut t, mut m) = start();
    let mut f = frame(TRANSFER, &[0]);
    f.push(0);
    t.receive(&f, 0, true, &mut m);
    assert_eq!(finish(&mut t, &mut m)[8], BAD_LENGTH);
    let f = extended(291, true);
    for p in f.chunks(64) {
        t.receive(p, 0, false, &mut m);
    }
    assert_eq!(finish(&mut t, &mut m)[8], BAD_LENGTH);
    assert_eq!(m.closes, 0);
}
#[test]
fn slot_parameter_precedence_and_zero_error_unsupported() {
    let (mut t, mut m) = start();
    for (cmd, payload, param, error, kind) in [
        (0xff, vec![], 0, 0, STATUS),
        (POWER_ON, vec![], 1, 7, DATA),
        (POWER_ON, vec![0], 1, 8, DATA),
        (SET_PARAMETERS, vec![], 0, 7, PARAMETERS),
        (SET_PARAMETERS, vec![0; 7], 1, 0, PARAMETERS),
        (GET_PARAMETERS, vec![], 0, 0, PARAMETERS),
        (RESET_PARAMETERS, vec![], 0, 0, PARAMETERS),
        (SLOT_STATUS, vec![0], 0, 8, STATUS),
    ] {
        let mut f = frame(cmd, &payload);
        f[7] = param;
        t.receive(&f, 0, true, &mut m);
        let r = finish(&mut t, &mut m);
        assert_eq!(r[0], kind);
        assert_eq!(r[8], error);
        assert_eq!(
            r[7] & 0x40,
            if error != 0 || cmd == 0xff { 0x40 } else { 0 }
        );
        if kind == PARAMETERS && error == 0 {
            assert_eq!(&r[10..], T1);
        }
    }
    let mut f = frame(TRANSFER, &[]);
    f[5] = 1;
    f[8] = 1;
    t.receive(&f, 0, true, &mut m);
    assert_eq!(finish(&mut t, &mut m)[8], BAD_SLOT);
    t.receive(&frame(POWER_OFF, &[]), 0, true, &mut m);
    assert_eq!(finish(&mut t, &mut m)[7], 1);
    t.receive(&frame(TRANSFER, &[]), 0, true, &mut m);
    assert_eq!(finish(&mut t, &mut m)[7..9], [0x41, MUTE]);
}
#[test]
fn leases_discovery_and_delayed_final_completion() {
    let (mut t, mut m) = start();
    assert!(!t.idle(1999));
    assert!(t.idle(2000));
    assert!(t.blocked_by_hid(Some(TRANSFER)));
    assert!(!t.blocked_by_hid(Some(SLOT_STATUS)));
    let resets = m.resets;
    t.receive(&frame(POWER_ON, &[]), 0, true, &mut m);
    let mut output = [0; HEADER + canokey_rust_core::runtime::ccid::REPLY];
    t.execute(true, &mut m, &mut output);
    assert_eq!(m.resets, resets);
    t.submitted();
    assert!(!t.can_receive());
    t.completed();
    t.receive(&frame(TRANSFER, &[0]), 0, true, &mut m);
    t.execute(false, &mut m, &mut output);
    let reply = t.reply(&output).unwrap().to_vec();
    t.receive(&frame(POWER_OFF, &[]), 0, true, &mut m);
    assert_eq!(t.reply(&output).unwrap(), reply);
    t.submitted();
    t.tx_timeout(2000, &mut m);
    assert_eq!(m.resets, resets + 1);
    t.tx_timeout(3000, &mut m);
    assert_eq!(m.resets, resets + 1);
    assert!(!t.can_receive());
    t.completed();
    assert!(t.can_receive());
}

#[test]
fn literal_discovery_and_rejected_command_headers() {
    // request, slot, response family, length, status, error, protocol number
    for [command, slot, kind, length, status, error, specific] in [
        [0x62, 0, 0x80, 17, 0, 0, 0],
        [0x63, 0, 0x81, 0, 1, 0, 0],
        [0x65, 0, 0x81, 0, 1, 0, 0],
        [0x6c, 0, 0x82, 7, 1, 0, 1],
        [0x6d, 0, 0x82, 7, 1, 0, 1],
        [0x61, 0, 0x82, 0, 0x41, 7, 1],
        [0x6b, 0, 0x83, 0, 0x41, 0, 0],
        [0x69, 0, 0x80, 0, 0x41, 0, 0],
        [0x72, 0, 0x81, 0, 0x41, 0, 0],
        [0x65, 1, 0x81, 0, 0x41, 5, 0],
        [0x6c, 1, 0x82, 0, 0x41, 5, 1],
        [0x62, 1, 0x80, 0, 0x41, 5, 0],
        [0x6d, 1, 0x82, 0, 0x41, 5, 1],
        [0x61, 1, 0x82, 0, 0x41, 5, 1],
        [0x6b, 1, 0x83, 0, 0x41, 5, 0],
        [0x69, 1, 0x80, 0, 0x41, 5, 0],
    ] {
        let mut t = Transport::new();
        let mut m = Mock::default();
        t.receive(&[command, 0, 0, 0, 0, slot, 0x37, 0, 0, 0], 0, true, &mut m);
        let reply = finish(&mut t, &mut m);
        assert_eq!(
            &reply[..10],
            &[kind, length, 0, 0, 0, slot, 0x37, status, error, specific],
            "command {command:02x}, slot {slot}"
        );
        assert_eq!(reply.len(), 10 + usize::from(length));
        if length == 7 {
            assert_eq!(&reply[10..], &[0x11, 0x10, 0, 0x15, 0, 0xfe, 0]);
        }
        if length == 17 {
            assert_eq!(
                &reply[10..],
                b"\x3b\xf7\x11\x00\x00\x81\x31\xfe\x65CanoKey\x99"
            );
        }
    }
}

#[test]
fn header_length_is_unaligned_little_endian_without_native_layout() {
    let input = [0x6f, 0x12, 0x34, 0x56, 0x78, 0, 0x37, 0, 0, 0];
    assert_eq!(payload_length(&input), 0x78563412);
    let mut output = [0xa5; 10];
    response(&mut output, 0x80, 0x78563412, 1, 0x37, 0x41, 5, 0);
    assert_eq!(output, [0x80, 0x12, 0x34, 0x56, 0x78, 1, 0x37, 0x41, 5, 0]);
}
