// SPDX-License-Identifier: Apache-2.0
//! Independent usage-table oracle around the real PASS output + keyboard policy.
extern crate std;
use std::{vec, vec::Vec};
use crate::{applets::pass::output::Output, ports::Memory, runtime::keyboard::Keyboard};
struct Erase;
impl Memory for Erase {
    fn wipe(&self, bytes: &mut [u8]) { bytes.fill(0); }
}
struct Harness {
    output: Output,
    keyboard: Keyboard,
    slots: [Vec<u8>; 2],
    calls: Vec<u8>,
    reports: Vec<Vec<u8>>,
}
impl Harness {
    fn new(short: &[u8], long: &[u8]) -> Self {
        let mut h = Self { output: Output::new(), keyboard: Keyboard::new(),
            slots: [short.into(), long.into()], calls: Vec::new(), reports: Vec::new() };
        h.poll(false, 1600, true);
        h
    }
    fn poll(&mut self, pressed: bool, now: u32, idle: bool) {
        let slots = &self.slots;
        let calls = &mut self.calls;
        let ch = self.output.sample(pressed, now, self.keyboard.ready(idle), &Erase,
            |slot, out| {
                calls.push(slot);
                let bytes = &slots[usize::from(slot)];
                out[..bytes.len()].copy_from_slice(bytes);
                bytes.len()
            });
        if !idle { assert_eq!(ch, None); return; }
        let mut report = [0xff; 8];
        let n = if ch == Some(3) { self.keyboard.prepare_eject(&mut report) }
            else { self.keyboard.prepare(ch, &mut report) };
        if let Some(n) = n {
            self.reports.push(report[..n].into());
            self.keyboard.accepted(report[0]);
        }
    }
    fn finish(&mut self, now: u32) {
        for tick in now..now + 160 { self.poll(false, tick, true); }
        assert!(!self.output.busy());
        assert!(self.keyboard.ready(true));
    }
    fn typed(&self) -> Vec<u8> {
        self.reports.iter().filter_map(|report| {
            if report[0] != 1 || report[3] == 0 { return None; }
            assert_eq!(report.len(), 8);
            assert!(report[4..].iter().all(|&b| b == 0));
            let shift = report[1] == 2;
            assert!(shift || report[1] == 0);
            Some(match report[3] {
                k @ 4..=29 => (if shift { b'A' } else { b'a' }) + k - 4,
                k @ 30..=38 => if shift { b"!@#$%^&*("[usize::from(k - 30)] } else { b'1' + k - 30 },
                39 => if shift { b')' } else { b'0' },
                40 => b'\r',
                44 => b' ',
                k @ 45..=56 if k != 50 => {
                    let table = if shift { b"_+{}|?:\"~<>?" } else { b"-=[]\\?;'`,./" };
                    table[usize::from(k - 45)]
                }
                other => panic!("invalid US keycode {other}"),
            })
        }).collect()
    }
}
#[test]
fn full_charset_enter_and_consumer_eject() {
    let charset: Vec<_> = (b' '..=b'~').collect();
    for chunk in charset.chunks(32).chain([b"ok\r".as_slice()]) {
        let mut h = Harness::new(chunk, b"");
        h.poll(true, 2000, true);
        h.poll(false, 2100, true);
        h.finish(2200);
        assert_eq!(h.typed(), chunk);
        assert_eq!(h.reports.len(), chunk.len() * 2);
        for pair in h.reports.chunks_exact(2) { assert_eq!(pair[1], [1, 0, 0, 0, 0, 0, 0, 0]); }
    }
    let mut h = Harness::new(b"", b"");
    h.output.eject(&Erase);
    h.finish(2000);
    assert_eq!(h.reports, [vec![2, 0xb8], vec![2, 0]]);
}
#[test]
fn touch_routing_empty_slot_and_no_touch() {
    let mut h = Harness::new(b"secret", b"long");
    h.finish(2000);
    assert!(h.calls.is_empty() && h.reports.is_empty());
    h.poll(true, 3000, true);
    h.poll(false, 3600, true);
    h.finish(3601);
    assert_eq!(h.calls, [1]);
    assert_eq!(h.typed(), b"long");
    let mut h = Harness::new(b"", b"");
    h.poll(true, 2000, true);
    h.poll(false, 2100, true);
    h.finish(2101);
    assert_eq!(h.calls, [0]);
    assert!(h.reports.is_empty());
}
#[test]
fn completed_touch_waits_for_text_and_final_key_release() {
    let mut h = Harness::new(b"xy", b"long");
    h.poll(true, 2000, true);
    h.poll(false, 2100, true); // x pressed; controller still owns this report
    h.poll(true, 2200, false);
    h.poll(false, 2300, false); // second gesture completes while first job runs
    assert_eq!(h.calls, [0]);
    assert_eq!(h.typed(), b"x");
    h.poll(false, 2400, true); // release x
    h.poll(false, 2401, true); // press y
    h.poll(false, 2402, false); // delayed completion must not resolve next job
    assert_eq!(h.calls, [0]);
    h.poll(false, 2403, true); // release y
    assert_eq!(h.calls, [0]);
    h.finish(2404);
    assert_eq!(h.calls, [0, 0]);
    assert_eq!(h.typed(), b"xyxy");
}
#[test]
fn pending_gesture_is_cleared_by_cancel_and_tracks_long_slot() {
    let mut h = Harness::new(b"xy", b"Z");
    h.poll(true, 2000, true);
    h.poll(false, 2100, true);
    h.poll(true, 2200, false);
    h.poll(false, 2800, false);
    h.finish(2801);
    assert_eq!(h.calls, [0, 1]);
    assert_eq!(h.typed(), b"xyZ");
    let mut h = Harness::new(b"xy", b"Z");
    h.poll(true, 2000, true);
    h.poll(false, 2100, true);
    h.poll(true, 2200, false);
    h.poll(false, 2300, false);
    h.output.inhibit(false, &Erase);
    h.finish(2400);
    assert_eq!(h.calls, [0]);
    assert_eq!(h.typed(), b"x");
}
