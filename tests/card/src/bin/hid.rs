// SPDX-License-Identifier: Apache-2.0
//! Full HID framing and applet execution with direct Rust capability fakes.
use canokey_ports::{Record, Storage};
use canokey_protocol::ctaphid as wire;
use canokey_rust_ffi::{
    CTAPHID_OutEvent, CTAPHID_RxCanAccept, ck_hid_executing, ck_hid_packet_reset, ck_hid_progress,
    composition::{core, hid},
};
use canokey_test_card::transport::{self, Fake, SCRATCH_BYTES};
use std::cell::RefCell;
const REPORT_BYTES: usize = 64;
const INITIAL_BYTES: usize = 57;
const CONTINUATION_BYTES: usize = 59;
const INLINE_BYTES: usize = 192;
const HID_IN: u8 = 0x82;
const HID_OUT: u8 = 2;
struct Hardware {
    ticks: u32,
    configured: bool,
    idle: bool,
    output: Vec<[u8; REPORT_BYTES]>,
    rearms: usize,
    injected: Vec<(u32, [u8; REPORT_BYTES])>,
    injections: usize,
    disconnect: Option<u32>,
}
thread_local! {
    static HW: RefCell<Hardware> = const { RefCell::new(Hardware {
        ticks: 0, configured: true, idle: true, output: Vec::new(), rearms: 0,
        injected: Vec::new(), injections: 0, disconnect: None,
    }) };
}
fn hw<T>(run: impl FnOnce(&mut Hardware) -> T) -> T {
    HW.with(|h| run(&mut h.borrow_mut()))
}
#[unsafe(no_mangle)]
extern "C" fn device_get_tick() -> u32 {
    hw(|h| h.ticks)
}
#[unsafe(no_mangle)]
extern "C" fn device_delay(ms: i32) {
    assert!(ms >= 0);
    hw(|h| h.ticks += ms as u32);
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_lock() -> u32 {
    0
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_unlock(mask: u32) {
    assert_eq!(mask, 0);
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_configured() -> u8 {
    hw(|h| u8::from(h.configured))
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_tx_idle(ep: u8) -> u8 {
    assert_eq!(ep, HID_IN);
    hw(|h| u8::from(h.idle))
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_receive(ep: u8) {
    assert_eq!(ep, HID_OUT);
    hw(|h| h.rearms += 1);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_usb_submit(ep: u8, bytes: *const u8, length: u16, zlp: u8) -> i32 {
    assert_eq!((ep, length, zlp), (HID_IN, REPORT_BYTES as u16, 0));
    let report = unsafe { bytes.cast::<[u8; REPORT_BYTES]>().read() };
    hw(|h| {
        assert!(h.output.len() < 128);
        h.output.push(report);
    });
    1
}
#[unsafe(no_mangle)]
extern "C" fn ck_ccid_idle() -> u8 {
    1
}
fn progress() -> bool {
    let (report, disconnect) = hw(|h| {
        h.ticks += 1;
        assert!(h.ticks < 100_000, "stuck applet execution");
        let report = if h.injected.first().is_some_and(|(at, _)| h.ticks >= *at) {
            h.injections += 1;
            Some(h.injected.remove(0).1)
        } else {
            None
        };
        let disconnect = h.disconnect.is_some_and(|at| h.ticks >= at);
        if disconnect {
            h.disconnect = None;
            h.configured = false;
        }
        (report, disconnect)
    });
    if let Some(report) = report {
        assert_ne!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
    }
    if disconnect {
        unsafe { ck_hid_packet_reset() };
    }
    unsafe { ck_hid_executing() == 0 || ck_hid_progress() != 0 }
}
fn packet(cid: u32, command: u8, length: usize) -> [u8; REPORT_BYTES] {
    let mut bytes = [0; REPORT_BYTES];
    bytes[..4].copy_from_slice(&cid.to_be_bytes());
    bytes[4] = command;
    bytes[5..7].copy_from_slice(&(length as u16).to_be_bytes());
    bytes
}
fn poll() {
    unsafe { hid::poll::<Fake>() };
}
fn feed(report: &[u8; REPORT_BYTES]) {
    assert_ne!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
    poll();
}
fn drain() {
    for _ in 0..100 {
        if unsafe { hid::active() } == 0 {
            transport::scratch(|s| assert_eq!(s.owner, 0));
            return;
        }
        poll();
    }
    panic!("HID failed to drain");
}
fn reset() {
    unsafe { ck_hid_packet_reset() };
    poll();
    hw(|h| {
        h.output.clear();
        h.injected.clear();
        h.injections = 0;
        h.disconnect = None;
    });
}
fn clear_output() {
    hw(|h| h.output.clear());
}
fn response(cid: u32, command: u8) -> Vec<u8> {
    hw(|h| {
        let mut result = Vec::new();
        let mut total = None;
        let mut sequence = 0;
        for report in &h.output {
            if u32::from_be_bytes(report[..4].try_into().unwrap()) != cid
                || report[4] == wire::KEEPALIVE
            {
                continue;
            }
            let offset = if total.is_none() {
                assert_eq!(report[4], command);
                let length = u16::from_be_bytes(report[5..7].try_into().unwrap()) as usize;
                assert!(length > 0 && length <= SCRATCH_BYTES);
                total = Some(length);
                7
            } else {
                assert_eq!(report[4], sequence);
                sequence += 1;
                5
            };
            let n = (total.unwrap() - result.len()).min(REPORT_BYTES - offset);
            result.extend_from_slice(&report[offset..offset + n]);
            if Some(result.len()) == total {
                return result;
            }
        }
        panic!("missing HID response {cid:08x}/{command:02x}");
    })
}
fn command(cid: u32, command: u8, body: &[u8]) {
    let mut report = packet(cid, command, body.len());
    let first = body.len().min(INITIAL_BYTES);
    report[7..7 + first].copy_from_slice(&body[..first]);
    feed(&report);
    for (seq, part) in body[first..].chunks(CONTINUATION_BYTES).enumerate() {
        let mut report = packet(cid, seq as u8, 0);
        report[5..5 + part.len()].copy_from_slice(part);
        feed(&report);
    }
    drain();
}
fn mailbox(cid: u32) {
    reset();
    let report = packet(cid, wire::PING, 0);
    let before = hw(|h| h.rearms);
    assert_ne!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
    assert_eq!(hw(|h| h.output.len()), 0);
    assert_eq!(unsafe { CTAPHID_RxCanAccept() }, 0);
    assert_eq!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
    assert_eq!(hw(|h| h.rearms), before);
    poll();
    drain();
    assert_eq!(hw(|h| (h.output.len(), h.output[0][4])), (1, wire::PING));
    assert_ne!(unsafe { CTAPHID_RxCanAccept() }, 0);
    assert!(hw(|h| h.rearms) > before);
    reset();
    for value in 0..50 {
        let mut report = packet(cid, wire::PING, 1);
        report[7] = value;
        assert_ne!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
        assert_eq!(hw(|h| h.output.len()), value as usize);
        poll();
        drain();
        assert_eq!(hw(|h| h.output[value as usize][7]), value);
        assert_ne!(unsafe { CTAPHID_RxCanAccept() }, 0);
    }
    for late in [false, true] {
        reset();
        hw(|h| h.ticks = 100);
        let mut report = packet(cid, wire::PING, 58);
        report[7..].fill(0x5a);
        feed(&report);
        assert_eq!(hw(|h| h.output.len()), 0);
        hw(|h| h.ticks = if late { 1000 } else { 700 });
        let mut report = packet(cid, 0, 0);
        report[5] = 0xa5;
        assert_ne!(unsafe { CTAPHID_OutEvent(report.as_ptr()) }, 0);
        hw(|h| h.ticks = 1100);
        poll();
        drain();
        if late {
            assert_eq!(response(cid, wire::ERROR), [5]);
        } else {
            let mut expected = vec![0x5a; 57];
            expected.push(0xa5);
            assert_eq!(response(cid, wire::PING), expected);
        }
    }
    reset();
}
// Extended FIDO GetInfo APDU; optional Le=0 requests the complete response.
const MSG_INFO: &[u8] = &[0x80, 0x10, 0, 0, 0, 0, 1, 4, 0, 0];
// Extended ISO GET RESPONSE with unlimited output.
const MORE: &[u8] = &[0, 0xc0, 0, 0, 0, 0, 0, 0, 0];
fn main() {
    transport::device_hooks(|| device_get_tick(), progress);
    assert_eq!(unsafe { core::install::<Fake>() }, 0);
    reset();
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    command(wire::BROADCAST, wire::INIT, &nonce);
    let init = response(wire::BROADCAST, wire::INIT);
    assert_eq!(init.len(), 17);
    assert_eq!(&init[..8], nonce);
    let cid = u32::from_be_bytes(init[8..12].try_into().unwrap());
    assert!(!matches!(cid, 0 | wire::BROADCAST));
    mailbox(cid);
    let data: Vec<_> = (0..SCRATCH_BYTES).map(|i| i as u8).collect();
    for length in [192, 193, 1024, 1033, 1288, SCRATCH_BYTES] {
        clear_output();
        let leases = transport::scratch(|s| s.leases);
        command(cid, wire::PING, &data[..length]);
        assert_eq!(response(cid, wire::PING), data[..length]);
        transport::scratch(|s| {
            assert_eq!(s.leases, leases + usize::from(length > INLINE_BYTES));
            assert_eq!(s.clears, s.leases);
        });
    }
    clear_output();
    let leases = transport::scratch(|s| s.leases);
    feed(&packet(cid, wire::PING, SCRATCH_BYTES + 1));
    drain();
    assert_eq!(response(cid, wire::ERROR), [3]);
    transport::scratch(|s| {
        assert_eq!(s.leases, leases);
        assert_eq!(s.owner, 0);
    });
    clear_output();
    command(cid, wire::CBOR, &[4]);
    let info = response(cid, wire::CBOR);
    assert!(info.len() > 256 && info[0] == 0);
    for length in [8, 10] {
        clear_output();
        command(cid, wire::MSG, &MSG_INFO[..length]);
        assert_eq!(
            response(cid, wire::MSG),
            [info.as_slice(), &[0x90, 0]].concat()
        );
    }
    let mut limited = MSG_INFO.to_vec();
    limited[9] = 1;
    clear_output();
    let mut report = packet(cid, wire::MSG, limited.len());
    report[7..7 + limited.len()].copy_from_slice(&limited);
    feed(&report);
    assert_eq!(response(cid, wire::MSG), [info[0], 0x61, 0xff]);
    assert_eq!(response(cid, wire::MSG), [info[0], 0x61, 0xff]);
    hw(|h| h.idle = false);
    let mut queued = packet(cid, wire::MSG, MORE.len());
    queued[7..7 + MORE.len()].copy_from_slice(MORE);
    feed(&queued);
    poll();
    assert_eq!(hw(|h| h.output.len()), 1);
    assert_ne!(unsafe { hid::active() }, 0);
    clear_output();
    hw(|h| h.idle = true);
    poll();
    drain();
    assert_eq!(response(cid, wire::MSG), [&info[1..], &[0x90, 0]].concat());
    clear_output();
    command(cid, wire::MSG, MORE);
    assert_eq!(response(cid, wire::MSG), [0x69, 0x86]);
    clear_output();
    command(cid, wire::MSG, &limited);
    clear_output();
    command(cid, wire::MSG, &[0x80, 0xc0, 0, 0, 17]);
    let window = response(cid, wire::MSG);
    assert_eq!(window.len(), 19);
    assert_eq!(&window[..17], &info[1..18]);
    assert_eq!(window[17], 0x61);
    clear_output();
    command(cid, wire::MSG, &[0, 0xc0, 0, 0, 0, 0, 0]);
    assert_eq!(response(cid, wire::MSG), [&info[18..], &[0x90, 0]].concat());
    for mode in 0..5 {
        clear_output();
        command(cid, wire::MSG, &limited);
        clear_output();
        match mode {
            0 => command(cid, wire::CBOR, &[4]),
            1 => command(cid, wire::INIT, &nonce),
            2 => {
                command(cid + 1, wire::MSG, MORE);
                assert_eq!(response(cid + 1, wire::MSG), [0x69, 0x86]);
            }
            3 => reset(),
            _ => {
                command(cid, wire::MSG, &[0, 0xc0, 1, 0, 0]);
                assert_eq!(response(cid, wire::MSG), [0x6a, 0x86]);
            }
        }
        clear_output();
        command(cid, wire::MSG, MORE);
        assert_eq!(response(cid, wire::MSG), [0x69, 0x86]);
    }
    // largeBlob get: 960 bytes at offset zero, then one byte beyond its end.
    transport::records(|s| s.replace(Record::CtapLargeBlob, &data[..960]).unwrap());
    const BLOB_GET: &[u8] = &[0x0c, 0xa2, 1, 0x19, 3, 0xc0, 3, 0];
    const BLOB_PREFIX: &[u8] = &[0, 0xa1, 1, 0x59, 3, 0xc0];
    clear_output();
    command(cid, wire::CBOR, BLOB_GET);
    assert_eq!(
        response(cid, wire::CBOR),
        [BLOB_PREFIX, &data[..960]].concat()
    );
    let mut blob_msg = vec![0x80, 0x10, 0, 0, BLOB_GET.len() as u8];
    blob_msg.extend_from_slice(BLOB_GET);
    blob_msg.push(53);
    clear_output();
    command(cid, wire::MSG, &blob_msg);
    let first = response(cid, wire::MSG);
    assert_eq!(first.len(), 55);
    assert_eq!(&first[..53], [BLOB_PREFIX, &data[..47]].concat());
    assert_eq!(first[53], 0x61);
    clear_output();
    command(cid, wire::MSG, MORE);
    assert_eq!(
        response(cid, wire::MSG),
        [&data[47..960], &[0x90, 0]].concat()
    );
    clear_output();
    command(cid, wire::CBOR, &[0x0c, 0xa2, 1, 1, 3, 0x19, 3, 0xc0]);
    assert_eq!(response(cid, wire::CBOR), [0, 0xa1, 1, 0x40]);
    // clientPIN getKeyAgreement with a valid ignored 700-byte extension.
    let mut pin = vec![6, 0xa3, 1, 1, 2, 2, 0x18, 0x7f, 0x59, 2, 0xbc];
    pin.extend_from_slice(&[0xa5; 700]);
    clear_output();
    command(cid, wire::CBOR, &pin);
    let reply = response(cid, wire::CBOR);
    assert!(reply.len() > 64 && reply[0] == 0);
    for mode in 0..4 {
        clear_output();
        let mut partial = packet(cid, wire::CBOR, 700);
        partial[7] = 6;
        feed(&partial);
        transport::scratch(|s| assert_ne!(s.owner, 0));
        match mode {
            0 => {
                feed(&packet(cid, 1, 0));
                drain();
                assert_eq!(response(cid, wire::ERROR), [4]);
            }
            1 => {
                hw(|h| h.ticks += 1000);
                poll();
                drain();
                assert_eq!(response(cid, wire::ERROR), [5]);
            }
            2 => {
                command(cid, wire::INIT, &nonce);
                assert_eq!(&response(cid, wire::INIT)[..8], nonce);
            }
            _ => reset(),
        }
        transport::scratch(|s| {
            assert_eq!(s.owner, 0);
            assert_eq!(s.leases, s.clears);
        });
        clear_output();
        command(cid, wire::PING, &data[..193]);
        assert_eq!(response(cid, wire::PING), data[..193]);
    }
    clear_output();
    let at = device_get_tick();
    hw(|h| {
        h.injected = vec![
            (at + 3, packet(cid + 1, wire::PING, 1)),
            (at + 6, packet(cid, wire::CANCEL, 0)),
        ]
    });
    command(cid, wire::CBOR, &[0x0b]);
    assert_eq!(hw(|h| h.injections), 2);
    assert_eq!(response(cid + 1, wire::ERROR), [6]);
    assert_eq!(response(cid, wire::CBOR), [0x2d]);
    assert!(hw(|h| h.output.iter().any(
        |r| r[4] == wire::KEEPALIVE && r[7] == wire::STATUS_UPNEEDED
    )));
    clear_output();
    let at = device_get_tick();
    let mut init = packet(cid, wire::INIT, nonce.len());
    init[7..15].copy_from_slice(&nonce);
    hw(|h| h.injected = vec![(at + 3, init)]);
    command(cid, wire::CBOR, &[0x0b]);
    poll();
    drain();
    assert_eq!(&response(cid, wire::INIT)[..8], nonce);
    assert!(hw(|h| h.output.iter().all(|r| r[4] != wire::CBOR)));
    clear_output();
    let at = device_get_tick();
    hw(|h| h.disconnect = Some(at + 3));
    command(cid, wire::CBOR, &[0x0b]);
    assert!(hw(|h| h.output.iter().all(|r| r[4] != wire::CBOR)));
    hw(|h| h.configured = true);
    reset();
    command(cid, wire::CBOR, &[4]);
    assert_eq!(response(cid, wire::CBOR), info);
    println!(
        "Rust HID core: mailbox, framing, staging, continuations, cancel/resync/disconnect passed"
    );
}
