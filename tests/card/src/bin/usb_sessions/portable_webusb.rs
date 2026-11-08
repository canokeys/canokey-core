// SPDX-License-Identifier: Apache-2.0
//! Literal EP0 stages using the production USB/WebUSB facade and real applets.
use super::*;
use std::io::{self, BufRead};

thread_local! {
    static DRAIN_EXECUTION_IN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXECUTION_IN: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

// The C adapter drains HID IN from its transmit hook. Match that explicit host
// schedule while Rust waits for an executing keepalive to complete. Only the
// IRQ-side completion runs here; never poll transports or reenter Core.
pub(super) fn drain_during_delay() {
    if DRAIN_EXECUTION_IN.get() && pending(usb_wire::EP_HID) {
        EXECUTION_IN.with(|bytes| bytes.borrow_mut().extend(packet(usb_wire::EP_HID)));
        complete(usb_wire::EP_HID_IN);
    }
}

pub(super) fn run(include_hid: bool) {
    DRAIN_EXECUTION_IN.set(include_hid);
    if std::env::args().nth(2).as_deref() == Some("--auto-touch") {
        // Host-only raw sensor waveform: normal Core presence code must still
        // observe a fresh press and release through serialized progress calls.
        transport::touch_hook(|| (20..60).contains(&(now() % 100)));
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if transport::records(|records| records.response_fault_control(&line)) {
            continue;
        }
        let (service, line) = match line.strip_prefix("DEFER ") {
            Some(line) => (false, line),
            None => (true, line.as_str()),
        };
        let (operation, value) = line.split_once(' ').unwrap();
        if operation == "TICK" {
            advance(value.parse().unwrap());
        } else {
            assert!(value.len() % 2 == 0 && value.len() <= 2 * PACKET_BYTES);
            let bytes: Vec<u8> = (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                .collect();
            match operation {
                "CCID" | "CLASS_CCID" => {
                    assert!(!bytes.is_empty());
                    assert_eq!(out(usb_wire::EP_CCID, &bytes), 0);
                }
                "HID" | "CLASS_HID" => {
                    assert!(include_hid && bytes.len() == PACKET_BYTES);
                    assert_eq!(out(usb_wire::EP_HID, &bytes), 0);
                }
                "SETUP" => {
                    assert_eq!(bytes.len(), 8);
                    unsafe { usb::setup(bytes.as_ptr(), bytes.len() as u16) };
                }
                "OUT" => {
                    out(0, &bytes);
                }
                "IN" => complete(usb_wire::DIRECTION_IN),
                "RESET" => {
                    hw(|h| {
                        h.address = 0;
                        h.pending.fill(false);
                        h.halted.fill(false);
                        h.opened.fill(false);
                        h.opened[0] = true;
                        h.opened[1] = true;
                    });
                    unsafe { usb::bus_reset() };
                }
                "POLL" => {}
                _ => panic!("unknown WebUSB operation"),
            }
        }
        if service {
            transport::presence_sample();
            unsafe { usb::service::<Fake>() };
            ccid_poll();
            if include_hid {
                hid_poll();
            }
            web_poll();
        }
        print!("WIRE ");
        if hw(|h| h.halted[0] || h.halted[1]) {
            print!("STALL");
        } else if pending(0) {
            for byte in packet(0) {
                print!("{byte:02x}");
            }
        }
        println!();
        if include_hid {
            print!("HID ");
            EXECUTION_IN.with(|bytes| {
                for byte in bytes.borrow_mut().drain(..) {
                    print!("{byte:02x}");
                }
            });
            for _ in 0..=hid_wire::CONTINUATION_COUNT {
                if !pending(usb_wire::EP_HID) {
                    break;
                }
                for byte in packet(usb_wire::EP_HID) {
                    print!("{byte:02x}");
                }
                complete(usb_wire::EP_HID_IN);
                hid_poll();
            }
            assert!(!pending(usb_wire::EP_HID));
            println!();
        }
        let mut bulk = Vec::new();
        for _ in 0..16 {
            if !pending(usb_wire::EP_CCID) {
                break;
            }
            bulk.extend(packet(usb_wire::EP_CCID));
            complete(usb_wire::EP_CCID_IN);
        }
        assert!(!pending(usb_wire::EP_CCID));
        print!("BULK ");
        for byte in bulk {
            print!("{byte:02x}");
        }
        println!();
    }
}
