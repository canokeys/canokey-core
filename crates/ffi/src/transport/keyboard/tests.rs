// SPDX-License-Identifier: Apache-2.0
use super::*;
use canokey_protocol::usb::{CONSUMER_REPORT_BYTES, KEYBOARD_PACKET_BYTES};

struct Fake {
    epoch: u32,
    busy: bool,
    fail: bool,
    reset_on_send: bool,
    competing: bool,
    web_busy: bool,
    configured: bool,
    contactless: bool,
    now: u32,
    consumed: usize,
    available: usize,
    samples: usize,
    cancelled: usize,
    submissions: usize,
    snapshot: [u8; KEYBOARD_PACKET_BYTES],
    length: usize,
}
impl Fake {
    fn complete(&mut self) {
        assert!(self.busy);
        // REPORT must stay unchanged for the entire controller-owned lease.
        let report = unsafe { &*core::ptr::addr_of!(REPORT) };
        assert_eq!(&report[..self.length], &self.snapshot[..self.length]);
        self.busy = false;
    }
}
impl Io for Fake {
    fn contactless(&mut self) -> bool {
        self.contactless
    }
    fn web_busy(&mut self) -> bool {
        self.web_busy
    }
    fn competing(&mut self) -> bool {
        self.competing
    }
    fn epoch(&mut self) -> u32 {
        self.epoch
    }
    fn configured(&mut self) -> bool {
        self.configured
    }
    fn idle(&mut self) -> bool {
        !self.busy
    }
    fn touched(&mut self) -> u8 {
        0
    }
    fn now(&mut self) -> u32 {
        self.now += 1;
        self.now
    }
    fn cancel(&mut self, _: u8) {
        self.cancelled += 1;
    }
    fn sample(&mut self, _: u8, _: u32, ready: bool) -> i32 {
        self.samples += 1;
        // Two identical keys, a shifted punctuation key, then consumer eject.
        const TEXT: [u8; 4] = [b'A', b'A', b'~', canokey_protocol::usb::EJECT_SENTINEL];
        if ready && self.consumed < self.available {
            let ch = TEXT[self.consumed];
            self.consumed += 1;
            i32::from(ch)
        } else {
            -1
        }
    }
    fn usage(&mut self, ch: u8) -> i32 {
        match ch {
            b'A' => 0x0204,
            b'~' => 0x0235,
            _ => -1,
        }
    }
    unsafe fn send(&mut self, report: *const u8, length: u8, epoch: u32) -> bool {
        assert!(!self.busy);
        assert!(matches!(
            usize::from(length),
            KEYBOARD_PACKET_BYTES | CONSUMER_REPORT_BYTES
        ));
        if self.reset_on_send {
            self.reset_on_send = false;
            self.epoch += 1;
        }
        if epoch != self.epoch {
            return false;
        }
        if self.fail {
            self.fail = false;
            return false;
        }
        self.length = usize::from(length);
        self.snapshot.fill(0);
        self.snapshot[..self.length]
            .copy_from_slice(unsafe { core::slice::from_raw_parts(report, self.length) });
        self.busy = true;
        self.submissions += 1;
        true
    }
}

// One serialized scenario owns the production singleton, matching firmware.
#[test]
fn keyboard_controller_leases_retries_preemption_and_reset() {
    let mut io = Fake {
        epoch: 1,
        busy: false,
        fail: false,
        reset_on_send: false,
        competing: true,
        web_busy: false,
        configured: true,
        contactless: false,
        now: 0,
        consumed: 0,
        available: 3,
        samples: 0,
        cancelled: 0,
        submissions: 0,
        snapshot: [0; KEYBOARD_PACKET_BYTES],
        length: 0,
    };
    unsafe {
        KEYBOARD = Keyboard::new();
        REPORT = [0; KEYBOARD_PACKET_BYTES];
        EPOCH = 0;
        PENDING = 0;
        RESET_OUTPUT = false;
        poll(&mut io);
        assert_eq!((io.samples, io.consumed, io.cancelled), (0, 0, 0));
        io.competing = false;
        io.fail = true;
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions, io.cancelled), (1, 0, 1));
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions), (1, 1));
        assert_eq!((io.snapshot[0], io.snapshot[1], io.snapshot[3]), (1, 2, 4));
        let before = io.samples;
        poll(&mut io);
        assert_eq!((io.samples, io.consumed), (before + 1, 1));
        io.complete();
        io.web_busy = true;
        let before = io.samples;
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions, io.samples), (1, 2, before));
        assert_eq!((io.snapshot[0], io.snapshot[1], io.snapshot[3]), (1, 0, 0));
        io.web_busy = false;
        poll(&mut io);
        assert_eq!(io.consumed, 1);
        io.complete();
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions), (2, 3));
        io.complete();
        poll(&mut io);
        io.complete();
        io.reset_on_send = true;
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions), (3, 4));
        poll(&mut io);
        assert_eq!((io.submissions, io.cancelled), (4, 2));
        io.available = 4;
        io.fail = true;
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions), (4, 4));
        poll(&mut io);
        assert_eq!((io.consumed, io.submissions), (4, 5));
        assert_eq!(
            (io.length, io.snapshot[0], io.snapshot[1]),
            (CONSUMER_REPORT_BYTES, 2, 0xb8)
        );
        io.complete();
        io.web_busy = true;
        poll(&mut io);
        assert_eq!(io.submissions, 6);
        assert_eq!(
            (io.length, io.snapshot[0], io.snapshot[1]),
            (CONSUMER_REPORT_BYTES, 2, 0)
        );
        io.complete();
        io.web_busy = false;
        io.epoch += 1;
        poll(&mut io);
        assert_eq!((io.submissions, io.cancelled), (6, 3));
        io.contactless = true;
        let before = io.samples;
        poll(&mut io);
        assert_eq!(io.samples, before);
        io.contactless = false;
        io.configured = false;
        poll(&mut io);
        assert_eq!(io.samples, before);
    }
}
