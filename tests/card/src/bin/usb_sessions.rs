// SPDX-License-Identifier: Apache-2.0
//! Real USB, CCID, HID, WebUSB and applets with direct Rust capability fakes.
#[cfg(feature = "piv")]
use canokey_ports::{Record, Storage};
use canokey_protocol::{ccid as ccid_wire, ctaphid as hid_wire, usb as usb_wire};
use canokey_rust_ffi::{
    ck_hid_executing,
    composition::{ccid, core, hid, usb, webusb},
};
use canokey_test_card::transport::{self, Fake, SCRATCH_BYTES};
use std::cell::RefCell;
const PACKET_BYTES: usize = usb_wire::DATA_PACKET_BYTES;
const CONTROL_BYTES: usize = usb_wire::EP0_PACKET_BYTES;
// CCID header plus a maximum short APDU response and its two-byte status word.
const RESPONSE_BYTES: usize = ccid_wire::HEADER + 256 + 2;
// Extended APDU header and Le surround the bounded standalone CTAP body.
const EXTENDED_APDU_BYTES: usize = 7 + hid_wire::CTAP_MAX_REQUEST + 2;
const LEASE_MS: u32 = 2000;
// SELECT ADMIN, verify factory PIN, query authorization and a one-byte config window.
const SELECT_ADMIN: &[u8] = &[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0];
const VERIFY: &[u8] = b"\x00\x20\x00\x00\x06123456";
const QUERY: &[u8] = &[0, 0x20, 0, 0];
const PARTIAL_CONFIG: &[u8] = &[0, 0x43, 0, 0, 1];
const NONCE: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
// FIDO GetInfo with extended Le=1; GET RESPONSE with omitted/short Le.
const LIMITED_MSG: &[u8] = &[0x80, 0x10, 0, 0, 0, 0, 1, 4, 0, 1];
const MSG_MORE: &[u8] = &[0, 0xc0, 0, 0, 0, 0, 0];
const GET_RESPONSE: &[u8] = &[0, 0xc0, 0, 0, 1];
const REST: &[u8] = &[0, 0xc0, 0, 0, 0];
// SELECT FIDO; short GetInfo with Le=1 leaves a file-backed response.
const SELECT_FIDO: &[u8] = &[0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1];
const INFO_SHORT: &[u8] = &[0x80, 0x10, 0, 0, 1, 4, 1];
struct Hardware {
    masked: u32,
    now: u32,
    address: u8,
    ready: bool,
    opened: [bool; 8],
    halted: [bool; 8],
    pending: [bool; 4],
    packets: [[u8; PACKET_BYTES]; 4],
    lengths: [usize; 4],
    submissions: [usize; 4],
    inject_after_unlock: usize,
    injected: Vec<u8>,
    sequence: u8,
    presence_stage: u8,
    presence_cid: u32,
}
thread_local! {
    static HW: RefCell<Hardware> = const { RefCell::new(Hardware {
        masked: 1, now: 0, address: 0, ready: false, opened: [false; 8],
        halted: [false; 8], pending: [false; 4], packets: [[0; PACKET_BYTES]; 4],
        lengths: [0; 4], submissions: [0; 4], inject_after_unlock: 0,
        injected: Vec::new(), sequence: 0, presence_stage: 0, presence_cid: 0,
    }) };
}
fn hw<T>(run: impl FnOnce(&mut Hardware) -> T) -> T {
    HW.with(|h| run(&mut h.borrow_mut()))
}
fn ix(ep: u8) -> usize {
    usize::from((ep & 3) * 2 + (ep >> 7))
}
fn endpoint(ep: u8) -> usize {
    usize::from(ep & usb_wire::ENDPOINT_NUMBER_MASK)
}
fn advance(ms: u32) {
    hw(|h| h.now = h.now.wrapping_add(ms));
}
fn now() -> u32 {
    hw(|h| h.now)
}
fn pending(ep: u8) -> bool {
    hw(|h| h.pending[endpoint(ep)])
}
fn packet(ep: u8) -> Vec<u8> {
    hw(|h| h.packets[endpoint(ep)][..h.lengths[endpoint(ep)]].to_vec())
}
fn sequence() -> u8 {
    hw(|h| h.sequence)
}
fn next_sequence() -> u8 {
    hw(|h| {
        h.sequence = h.sequence.wrapping_add(1);
        h.sequence
    })
}
#[unsafe(no_mangle)]
extern "C" fn device_get_tick() -> u32 {
    now()
}
#[unsafe(no_mangle)]
extern "C" fn device_delay(ms: i32) {
    assert!(ms >= 0);
    advance(ms as u32);
}
#[unsafe(no_mangle)]
extern "C" fn device_set_timeout(_: Option<unsafe extern "C" fn()>, _: u16) {}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_lock() -> u32 {
    hw(|h| {
        let mask = h.masked;
        h.masked = 1;
        mask
    })
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_unlock(mask: u32) {
    let injected = hw(|h| {
        h.masked = mask;
        if mask == 0 && h.inject_after_unlock != 0 {
            h.inject_after_unlock -= 1;
            if h.inject_after_unlock == 0 {
                return Some(h.injected.clone());
            }
        }
        None
    });
    if let Some(bytes) = injected {
        assert_eq!(out(usb_wire::EP_CCID, &bytes), 0);
    }
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_start() {
    hw(|h| assert_ne!(h.masked, 0));
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_enable_irq() {
    hw(|h| assert_ne!(h.masked, 0));
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_stop() {
    hw(|h| assert_ne!(h.masked, 0));
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_open(ep: u8) {
    hw(|h| {
        assert_ne!(h.masked, 0);
        h.opened[ix(ep)] = true;
        h.halted[ix(ep)] = false;
    });
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_close(ep: u8) {
    hw(|h| {
        assert_ne!(h.masked, 0);
        h.opened[ix(ep)] = false;
        if ep & usb_wire::DIRECTION_IN != 0 {
            h.pending[endpoint(ep)] = false;
        }
    });
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_stall(ep: u8, halt: u8) {
    hw(|h| {
        assert_ne!(h.masked, 0);
        h.halted[ix(ep)] = halt != 0;
    });
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_address(address: u8) {
    hw(|h| {
        assert_ne!(h.masked, 0);
        h.address = address;
    });
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_ready(ready: u8) {
    hw(|h| {
        assert_ne!(h.masked, 0);
        h.ready = ready != 0;
    });
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_receive(ep: u8) {
    hw(|h| assert!(h.masked != 0 && h.opened[ix(ep)]));
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_usb_dcd_write(ep: u8, bytes: *const u8, length: u16) -> u8 {
    hw(|h| {
        let index = endpoint(ep);
        assert!(
            h.masked != 0
                && h.opened[ix(ep)]
                && ep & usb_wire::DIRECTION_IN != 0
                && !h.pending[index]
        );
        let n = usize::from(length);
        assert!(
            n <= if index == 0 {
                CONTROL_BYTES
            } else {
                PACKET_BYTES
            }
        );
        if n != 0 {
            h.packets[index][..n].copy_from_slice(unsafe { std::slice::from_raw_parts(bytes, n) });
        }
        h.lengths[index] = n;
        h.pending[index] = true;
        h.submissions[index] += 1;
        1
    })
}
fn out(ep: u8, bytes: &[u8]) -> u8 {
    unsafe { usb::out_event(ep, bytes.as_ptr(), bytes.len() as u16) }
}
fn complete(ep: u8) {
    hw(|h| {
        assert!(h.pending[endpoint(ep)]);
        h.pending[endpoint(ep)] = false;
    });
    unsafe { usb::in_event(ep) };
}
fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) {
    let mut bytes = [kind, request, 0, 0, 0, 0, 0, 0];
    bytes[2..4].copy_from_slice(&value.to_le_bytes());
    bytes[4..6].copy_from_slice(&index.to_le_bytes());
    bytes[6..8].copy_from_slice(&length.to_le_bytes());
    unsafe { usb::setup(bytes.as_ptr(), bytes.len() as u16) };
}
fn status() {
    assert!(pending(0) && packet(0).is_empty());
    complete(usb_wire::DIRECTION_IN);
}
fn read_control() -> Vec<u8> {
    let mut result = Vec::new();
    while pending(0) {
        result.extend(packet(0));
        assert!(result.len() <= 256);
        complete(usb_wire::DIRECTION_IN);
    }
    assert_eq!(out(0, &[]), 1);
    result
}
fn configure() {
    unsafe { usb::init() };
    hw(|h| assert!(h.masked != 0 && h.address == 0 && !h.ready));
    setup(0, usb_wire::SET_ADDRESS, 17, 0, 0);
    hw(|h| assert_eq!(h.address, 17));
    status();
    setup(0, usb_wire::SET_CONFIGURATION, 1, 0, 0);
    assert!(hw(|h| h.ready) && unsafe { usb::configured() } != 0);
    status();
}
fn ccid_poll() {
    unsafe { ccid::poll::<Fake>() };
}
fn hid_poll() {
    unsafe { hid::poll::<Fake>() };
}
fn web_poll() {
    unsafe { webusb::poll::<Fake>() };
}
fn loops() {
    ccid_poll();
    hid_poll();
    web_poll();
}
fn sw(bytes: &[u8], expected: u16) {
    assert!(bytes.len() >= 2);
    assert_eq!(
        u16::from_be_bytes(bytes[bytes.len() - 2..].try_into().unwrap()),
        expected
    );
}
fn ccid_request(command: u8, apdu: &[u8], sequence: u8) -> Vec<u8> {
    let mut request = vec![0; ccid_wire::HEADER];
    request[0] = command;
    request[1..5].copy_from_slice(&(apdu.len() as u32).to_le_bytes());
    request[ccid_wire::SEQUENCE_OFFSET] = sequence;
    request.extend_from_slice(apdu);
    request
}
fn ccid_send(command: u8, apdu: &[u8]) {
    assert!(apdu.len() <= EXTENDED_APDU_BYTES);
    let request = ccid_request(command, apdu, next_sequence());
    for part in request.chunks(PACKET_BYTES) {
        assert_eq!(out(usb_wire::EP_CCID, part), 0);
        ccid_poll();
    }
}
fn ccid_read_state(state: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..20 {
        ccid_poll();
        if !pending(usb_wire::EP_CCID) {
            break;
        }
        bytes.extend(packet(usb_wire::EP_CCID));
        assert!(bytes.len() <= RESPONSE_BYTES);
        complete(usb_wire::EP_CCID_IN);
    }
    ccid_poll();
    assert!(bytes.len() >= ccid_wire::HEADER);
    assert_eq!((bytes[6], bytes[7], bytes[8]), (sequence(), state, 0));
    assert_eq!(
        bytes.len(),
        ccid_wire::HEADER + u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize
    );
    bytes
}
fn ccid_read() -> Vec<u8> {
    ccid_read_state(0)
}
fn ccid_apdu(apdu: &[u8], expected: u16) {
    ccid_send(ccid_wire::TRANSFER, apdu);
    sw(&ccid_read()[ccid_wire::HEADER..], expected);
}
fn web_send(apdu: &[u8]) {
    assert!(apdu.len() <= CONTROL_BYTES);
    setup(0x41, 0, 0, 1, apdu.len() as u16);
    assert_eq!(out(0, apdu), 0);
    web_poll();
    if pending(0) {
        status();
    }
}
fn web_apdu(apdu: &[u8], expected: u16) {
    web_send(apdu);
    assert!(!hw(|h| h.halted[1]));
    setup(0xc1, 1, 0, 1, 256);
    sw(&read_control(), expected);
}
fn hid_packet(cid: u32, command: u8, length: usize) -> [u8; PACKET_BYTES] {
    let mut report = [0; PACKET_BYTES];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = command;
    report[5..7].copy_from_slice(&(length as u16).to_be_bytes());
    report
}
fn hid_send(cid: u32, command: u8, body: &[u8]) {
    assert!(body.len() <= hid_wire::CTAP_MAX_REQUEST);
    let mut report = hid_packet(cid, command, body.len());
    let first = body
        .len()
        .min(PACKET_BYTES - hid_wire::INITIAL_HEADER_BYTES);
    report[7..7 + first].copy_from_slice(&body[..first]);
    assert_eq!(out(usb_wire::EP_HID, &report), 0);
    hid_poll();
    for (sequence, part) in body[first..]
        .chunks(PACKET_BYTES - hid_wire::CONTINUATION_HEADER_BYTES)
        .enumerate()
    {
        let mut report = hid_packet(cid, sequence as u8, 0);
        report[5..5 + part.len()].copy_from_slice(part);
        assert_eq!(out(usb_wire::EP_HID, &report), 0);
        hid_poll();
    }
}
fn hid_read(cid: u32, command: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut total = 0;
    let mut sequence = 0;
    for _ in 0..30 {
        hid_poll();
        if !pending(usb_wire::EP_HID) {
            assert_eq!(unsafe { hid::active() }, 0);
            break;
        }
        let report = packet(usb_wire::EP_HID);
        assert_eq!(report.len(), PACKET_BYTES);
        assert_eq!(u32::from_be_bytes(report[..4].try_into().unwrap()), cid);
        let offset = if bytes.is_empty() {
            assert_eq!(report[4], command);
            total = usize::from(u16::from_be_bytes(report[5..7].try_into().unwrap()));
            7
        } else {
            assert_eq!(report[4], sequence);
            sequence += 1;
            5
        };
        assert!(total > 0 && total <= 1100);
        let n = (total - bytes.len()).min(PACKET_BYTES - offset);
        bytes.extend_from_slice(&report[offset..offset + n]);
        complete(usb_wire::EP_HID_IN);
    }
    assert_eq!(bytes.len(), total);
    assert_eq!(unsafe { hid::active() }, 0);
    bytes
}
fn echo(cid: u32) {
    hid_send(cid, hid_wire::PING, NONCE);
    assert_eq!(hid_read(cid, hid_wire::PING), NONCE);
}
fn clean_scratch() {
    transport::scratch(|s| {
        assert_eq!(s.owner, 0);
        assert_eq!(s.leases, s.clears);
    });
}
fn progress() -> bool {
    advance(1);
    if hw(|h| h.presence_stage != 0) {
        presence_progress();
    }
    unsafe { usb::progress::<Fake>() != 0 }
}
fn presence_progress() {
    assert_ne!(unsafe { ck_hid_executing() }, 0);
    if pending(usb_wire::EP_HID) {
        complete(usb_wire::EP_HID_IN);
    }
    let stage = hw(|h| h.presence_stage);
    let mut poll = ccid_request(ccid_wire::SLOT_STATUS, &[], 0x37);
    match stage {
        1 => {
            assert_eq!(out(usb_wire::EP_CCID, &poll), 0);
        }
        2 => {
            assert_eq!(
                packet(usb_wire::EP_CCID),
                [ccid_wire::STATUS, 0, 0, 0, 0, 0, 0x37, 0, 0, 0]
            );
            poll[6] = 0x38;
            assert_eq!(out(usb_wire::EP_CCID, &poll), 0);
        }
        3 => {
            assert!(pending(usb_wire::EP_CCID));
            assert_eq!(packet(usb_wire::EP_CCID)[6], 0x37);
            complete(usb_wire::EP_CCID_IN);
        }
        4 => {
            assert_eq!(
                packet(usb_wire::EP_CCID),
                [ccid_wire::STATUS, 0, 0, 0, 0, 0, 0x38, 0, 0, 0]
            );
            complete(usb_wire::EP_CCID_IN);
            poll[0] = ccid_wire::POWER_ON;
            poll[6] = 0x39;
            assert_eq!(out(usb_wire::EP_CCID, &poll), 0);
        }
        5 => {
            assert!(!pending(usb_wire::EP_CCID));
            let cid = hw(|h| h.presence_cid);
            assert_eq!(
                out(usb_wire::EP_HID, &hid_packet(cid, hid_wire::CANCEL, 0)),
                0
            );
        }
        _ => panic!("unexpected presence stage"),
    }
    hw(|h| h.presence_stage = if stage == 5 { 0 } else { stage + 1 });
}
fn main() {
    transport::device_hooks(now, progress);
    assert_eq!(unsafe { core::install::<Fake>() }, 0);
    configure();
    loops();
    explicit_selection();
    let cid = ownership_and_pending();
    preemption(cid);
    applet_streams();
    power_and_irq(cid);
    staging_and_presence(cid);
    println!("USB shared session correctness passed");
}

fn explicit_selection() {
    for chained in [false, true] {
        ccid_send(ccid_wire::POWER_ON, &[]);
        ccid_read();
        ccid_apdu(&[0x80, 0x10, 0, 0, 1, 4, 0], 0x6a82);
        ccid_apdu(&[0, 3, 0, 0, 0], 0x6a82);
        ccid_apdu(&[0x90, 0x10, 0, 0, 1, 4], 0x6a82);
        ccid_apdu(SELECT_FIDO, 0x9000);
        // P1=80 permits NFC polling semantics over CCID; optional ISO input chain.
        let mut info = [0x80, 0x10, 0x80, 0, 1, 4, 0];
        if chained {
            info[0] = 0x90;
            ccid_send(ccid_wire::TRANSFER, &info);
            let bytes = ccid_read();
            assert_eq!(bytes.len(), ccid_wire::HEADER + 2);
            sw(&bytes[ccid_wire::HEADER..], 0x9000);
            ccid_send(ccid_wire::TRANSFER, &[0x80, 0x10, 0x80, 0, 0]);
        } else {
            ccid_send(ccid_wire::TRANSFER, &info);
        }
        let mut bytes = ccid_read();
        let mut total = bytes.len() - ccid_wire::HEADER - 2;
        assert!(bytes.len() > ccid_wire::HEADER + 2 && bytes[10] == 0 && bytes[11] & 0xe0 == 0xa0);
        assert_eq!(bytes[bytes.len() - 2], 0x61);
        let mut chunks = 0;
        while bytes[bytes.len() - 2] == 0x61 {
            assert!(chunks < 8);
            chunks += 1;
            ccid_send(ccid_wire::TRANSFER, REST);
            bytes = ccid_read();
            total += bytes.len() - ccid_wire::HEADER - 2;
        }
        sw(&bytes[ccid_wire::HEADER..], 0x9000);
        assert!(total > 256);
    }
}
fn ownership_and_pending() -> u32 {
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(VERIFY, 0x9000);
    advance(LEASE_MS);
    loops();
    ccid_apdu(QUERY, 0x9000);
    ccid_apdu(PARTIAL_CONFIG, 0x6101);
    advance(LEASE_MS - 1);
    web_send(SELECT_ADMIN);
    assert!(hw(|h| h.halted[1]));
    ccid_apdu(QUERY, 0x9000); // Refused takeover cannot revoke the owner grant.
    advance(LEASE_MS);
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(QUERY, 0x63c3);
    web_apdu(VERIFY, 0x9000);
    web_apdu(QUERY, 0x9000);
    advance(LEASE_MS);
    loops();
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    ccid_apdu(VERIFY, 0x9000);
    hid_send(hid_wire::BROADCAST, hid_wire::INIT, NONCE);
    let init = hid_read(hid_wire::BROADCAST, hid_wire::INIT);
    assert_eq!(init.len(), 17);
    assert_eq!(&init[..8], NONCE);
    let cid = u32::from_be_bytes(init[8..12].try_into().unwrap());
    assert!(!matches!(cid, 0 | hid_wire::BROADCAST));
    ccid_apdu(PARTIAL_CONFIG, 0x6101);
    advance(LEASE_MS - 1);
    hid_send(cid, hid_wire::PING, NONCE);
    assert_eq!(hid_read(cid, hid_wire::ERROR), [6]);
    ccid_apdu(QUERY, 0x9000);
    advance(LEASE_MS);
    echo(cid);
    hid_send(cid, hid_wire::CBOR, &[4]);
    assert!(pending(usb_wire::EP_HID));
    let saved = packet(usb_wire::EP_HID);
    web_send(SELECT_ADMIN);
    assert!(hw(|h| h.halted[1]));
    ccid_send(ccid_wire::TRANSFER, SELECT_ADMIN);
    assert!(!pending(usb_wire::EP_CCID));
    assert_eq!(packet(usb_wire::EP_HID), saved);
    let info = hid_read(cid, hid_wire::CBOR);
    assert!(info.len() > 256 && info[0] == 0);
    advance(LEASE_MS - 1);
    ccid_poll();
    assert!(!pending(usb_wire::EP_CCID));
    advance(1);
    sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    ccid_apdu(VERIFY, 0x9000);
    // Continuation backing has the same two-second lease across competitors.
    for via_web in [false, true] {
        hid_send(cid, hid_wire::MSG, LIMITED_MSG);
        let bytes = hid_read(cid, hid_wire::MSG);
        assert!(bytes.len() == 3 && bytes[0] == 0 && bytes[1] == 0x61);
        if via_web {
            web_send(SELECT_ADMIN);
            assert!(hw(|h| h.halted[1]));
            advance(LEASE_MS);
            web_apdu(SELECT_ADMIN, 0x9000);
        } else {
            ccid_send(ccid_wire::TRANSFER, SELECT_ADMIN);
            advance(LEASE_MS - 1);
            ccid_poll();
            assert!(!pending(usb_wire::EP_CCID));
            advance(1);
            sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
        }
        hid_send(cid, hid_wire::MSG, MSG_MORE);
        assert_eq!(hid_read(cid, hid_wire::MSG), [0x69, 0x86]);
        advance(LEASE_MS);
        ccid_apdu(SELECT_ADMIN, 0x9000);
        ccid_apdu(VERIFY, 0x9000);
    }
    unsafe { usb::deinit() };
    configure();
    loops();
    ccid_send(ccid_wire::POWER_ON, &[]);
    ccid_read();
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    hw(|h| h.now = u32::MAX - 1000);
    ccid_apdu(VERIFY, 0x9000);
    ccid_apdu(PARTIAL_CONFIG, 0x6101);
    advance(LEASE_MS - 1);
    web_send(SELECT_ADMIN);
    assert!(hw(|h| h.halted[1]));
    advance(1);
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(QUERY, 0x63c3);
    advance(LEASE_MS);
    loops();
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(VERIFY, 0x9000);
    // A second OUT stays queued while the first CCID IN owns its immutable bytes.
    let first = ccid_request(ccid_wire::TRANSFER, QUERY, next_sequence());
    let next = ccid_request(
        ccid_wire::TRANSFER,
        &[0, 0xfe, 0, 0],
        sequence().wrapping_add(1),
    );
    assert_eq!(out(usb_wire::EP_CCID, &first), 0);
    assert_eq!(out(usb_wire::EP_CCID, &next), 0);
    ccid_poll();
    assert!(pending(usb_wire::EP_CCID));
    let saved = packet(usb_wire::EP_CCID);
    assert_eq!(saved.len(), ccid_wire::HEADER + 2);
    assert_eq!(saved[6], sequence());
    sw(&saved[ccid_wire::HEADER..], 0x9000);
    web_send(SELECT_ADMIN);
    assert!(hw(|h| h.halted[1]));
    assert_eq!(out(usb_wire::EP_CCID, &next), 0);
    assert_eq!(out(usb_wire::EP_CCID, &first), 0);
    ccid_poll();
    assert!(pending(usb_wire::EP_CCID));
    assert_eq!(packet(usb_wire::EP_CCID), saved);
    complete(usb_wire::EP_CCID_IN);
    next_sequence();
    sw(&ccid_read()[ccid_wire::HEADER..], 0x6d00);
    assert!(!pending(usb_wire::EP_CCID));
    cid
}
fn preemption(cid: u32) {
    loops();
    ccid_apdu(QUERY, 0x9000);
    let before = now();
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(QUERY, 0x63c3);
    assert_eq!(now(), before);
    advance(LEASE_MS);
    loops();
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(VERIFY, 0x9000);
    let before = now();
    echo(cid);
    assert_eq!(now(), before);
    advance(LEASE_MS);
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(VERIFY, 0x9000);
    let before = now();
    loops();
    web_apdu(QUERY, 0x9000);
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    ccid_apdu(VERIFY, 0x9000);
    assert_eq!(now(), before);
    advance(LEASE_MS);
    web_poll();
    ccid_apdu(QUERY, 0x9000);
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(VERIFY, 0x9000);
    let before = now();
    echo(cid);
    assert_eq!(now(), before);
    advance(LEASE_MS);
    loops();
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(VERIFY, 0x9000);
    web_apdu(PARTIAL_CONFIG, 0x6101);
    ccid_send(ccid_wire::TRANSFER, SELECT_ADMIN);
    assert!(!pending(usb_wire::EP_CCID));
    advance(LEASE_MS - 1);
    ccid_poll();
    assert!(!pending(usb_wire::EP_CCID));
    web_apdu(GET_RESPONSE, 0x9000);
    sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    // EP0 retains exclusive ownership until its IN data and status complete.
    web_apdu(SELECT_ADMIN, 0x9000);
    web_send(VERIFY);
    setup(0xc1, 1, 0, 1, 256);
    assert!(pending(0));
    let saved = packet(0);
    ccid_send(ccid_wire::TRANSFER, SELECT_ADMIN);
    assert!(!pending(usb_wire::EP_CCID));
    assert!(pending(0));
    assert_eq!(packet(0), saved);
    sw(&read_control(), 0x9000);
    sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    for command in [hid_wire::INIT, hid_wire::CANCEL] {
        web_apdu(SELECT_ADMIN, 0x9000);
        web_apdu(VERIFY, 0x9000);
        hid_send(
            if command == hid_wire::INIT {
                hid_wire::BROADCAST
            } else {
                cid
            },
            command,
            if command == hid_wire::INIT {
                NONCE
            } else {
                &[]
            },
        );
        assert!(!pending(usb_wire::EP_HID));
        web_apdu(QUERY, 0x9000);
        advance(LEASE_MS);
        web_poll();
        hid_poll();
        if command == hid_wire::INIT {
            assert_eq!(hid_read(hid_wire::BROADCAST, command).len(), 17);
        } else {
            assert!(!pending(usb_wire::EP_HID));
        }
    }
}
fn applet_streams() {
    ccid_apdu(SELECT_FIDO, 0x9000);
    ccid_apdu(INFO_SHORT, 0x61ff);
    let before = now();
    web_apdu(GET_RESPONSE, 0x6986);
    assert_eq!(now(), before);
    ccid_apdu(SELECT_FIDO, 0x9000);
    ccid_apdu(GET_RESPONSE, 0x6986);
    #[cfg(feature = "openpgp")]
    {
        // OpenPGP selection, PW3/PW1 and a three-byte certificate file source.
        const SELECT: &[u8] = &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1];
        const VERIFY_PW3: &[u8] = b"\x00\x20\x00\x83\x0812345678";
        const PUT_CERT: &[u8] = b"\x00\xda\x7f\x21\x03abc";
        const READ_CERT: &[u8] = &[0, 0xca, 0x7f, 0x21, 1];
        const VERIFY_PW1: &[u8] = b"\x00\x20\x00\x81\x06123456";
        const QUERY_PW1: &[u8] = &[0, 0x20, 0, 0x81];
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(VERIFY_PW3, 0x9000);
        ccid_apdu(PUT_CERT, 0x9000);
        ccid_apdu(READ_CERT, 0x6102);
        let before = now();
        web_apdu(GET_RESPONSE, 0x6986);
        assert_eq!(now(), before);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(GET_RESPONSE, 0x6986);
        ccid_apdu(&[0, 0x20, 0, 0x83], 0x63c3);
        ccid_apdu(VERIFY_PW1, 0x9000);
        advance(LEASE_MS + 1);
        loops();
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(QUERY_PW1, 0x9000);
        advance(LEASE_MS + 1);
        web_apdu(SELECT_ADMIN, 0x9000);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(QUERY_PW1, 0x63c3);
    }
    #[cfg(feature = "piv")]
    {
        // Opaque PivObject0 (5FC105); object data is TLV 53 length 1 value 07.
        transport::records(|s| s.replace(Record::PivObject0, &[0x53, 1, 7]).unwrap());
        const SELECT: &[u8] = &[0, 0xa4, 4, 0, 11, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0];
        const RID: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8];
        const VERIFY_PIN: &[u8] = b"\x00\x20\x00\x80\x08123456\xff\xff";
        const QUERY_PIN: &[u8] = &[0, 0x20, 0, 0x80];
        const READ_OBJECT: &[u8] = &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 1];
        const DISCOVERY: &[u8] = &[0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 1];
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(VERIFY_PIN, 0x9000);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(QUERY_PIN, 0x9000);
        ccid_apdu(RID, 0x9000);
        ccid_apdu(QUERY_PIN, 0x9000);
        ccid_apdu(SELECT_ADMIN, 0x9000);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(QUERY_PIN, 0x63c3);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(DISCOVERY, 0x6113);
        web_send(SELECT_ADMIN);
        assert!(hw(|h| h.halted[1]));
        ccid_apdu(REST, 0x9000);
        ccid_apdu(READ_OBJECT, 0x6102);
        let before = now();
        web_apdu(GET_RESPONSE, 0x6986);
        assert_eq!(now(), before);
        ccid_apdu(SELECT, 0x9000);
        ccid_apdu(GET_RESPONSE, 0x6986);
    }
}
fn power_and_irq(cid: u32) {
    for command in [ccid_wire::POWER_ON, ccid_wire::POWER_OFF] {
        web_apdu(SELECT_ADMIN, 0x9000);
        web_apdu(VERIFY, 0x9000);
        let before = now();
        ccid_send(command, &[]);
        let bytes = ccid_read_state(u8::from(command == ccid_wire::POWER_OFF));
        assert_eq!(now(), before);
        if command == ccid_wire::POWER_ON {
            assert!(bytes.len() > ccid_wire::HEADER);
            assert_eq!(bytes[0], ccid_wire::DATA);
        } else {
            assert_eq!(
                (bytes.len(), bytes[0]),
                (ccid_wire::HEADER, ccid_wire::STATUS)
            );
            ccid_send(ccid_wire::POWER_ON, &[]);
            ccid_read();
        }
        ccid_apdu(SELECT_ADMIN, 0x9000);
        ccid_apdu(QUERY, 0x63c3);
        ccid_apdu(VERIFY, 0x9000);
        advance(LEASE_MS);
        web_poll();
        ccid_apdu(QUERY, 0x9000);
    }
    web_apdu(SELECT_ADMIN, 0x9000);
    web_apdu(VERIFY, 0x9000);
    web_apdu(PARTIAL_CONFIG, 0x6101);
    ccid_send(ccid_wire::POWER_ON, &[]);
    assert!(!pending(usb_wire::EP_CCID));
    advance(LEASE_MS - 1);
    ccid_poll();
    assert!(!pending(usb_wire::EP_CCID));
    web_apdu(GET_RESPONSE, 0x9000);
    let bytes = ccid_read();
    assert_eq!((bytes[0], bytes[7]), (ccid_wire::DATA, 0));
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    ccid_apdu(SELECT_FIDO, 0x9000);
    ccid_send(ccid_wire::TRANSFER, INFO_SHORT);
    assert!(pending(usb_wire::EP_CCID));
    let saved = packet(usb_wire::EP_CCID);
    hid_send(cid, hid_wire::PING, NONCE);
    assert_eq!(hid_read(cid, hid_wire::ERROR), [6]);
    assert!(pending(usb_wire::EP_CCID));
    assert_eq!(packet(usb_wire::EP_CCID), saved);
    sw(&ccid_read()[ccid_wire::HEADER..], 0x61ff);
    let before = now();
    echo(cid);
    assert_eq!(now(), before);
    advance(LEASE_MS);
    ccid_apdu(GET_RESPONSE, 0x6986);
    // Sweep IRQ publication over every unlocked boundary reached by CCID poll.
    let mut exercised = 0;
    for boundary in 1..=8 {
        echo(cid);
        let injected = ccid_request(ccid_wire::TRANSFER, SELECT_ADMIN, next_sequence());
        hw(|h| {
            h.injected = injected;
            h.inject_after_unlock = boundary;
            h.masked = 0;
        });
        ccid_poll();
        hw(|h| h.masked = 1);
        if hw(|h| h.inject_after_unlock != 0) {
            hw(|h| h.inject_after_unlock = 0);
            advance(LEASE_MS);
            break;
        }
        exercised += 1;
        assert!(!pending(usb_wire::EP_CCID));
        transport::scratch(|s| assert_eq!(s.owner, 0));
        ccid_poll();
        assert!(!pending(usb_wire::EP_CCID));
        advance(LEASE_MS - 1);
        ccid_poll();
        assert!(!pending(usb_wire::EP_CCID));
        advance(1);
        sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
    }
    assert!(exercised > 0);
}
fn staging_and_presence(cid: u32) {
    use canokey_rust_ffi::composition::Staging;
    use canokey_test_card::transport::Scratch;
    let fragmented = hid_packet(cid, hid_wire::PING, 193);
    for command in [
        ccid_wire::POWER_OFF,
        ccid_wire::POWER_ON,
        ccid_wire::SLOT_STATUS,
    ] {
        assert_eq!(out(usb_wire::EP_HID, &fragmented), 0);
        hid_poll();
        let held = transport::scratch(|s| {
            assert_ne!(s.owner, 0);
            (s.owner, s.leases, s.clears)
        });
        let mut staged = [0; SCRATCH_BYTES];
        assert!(Scratch::read(0, &mut staged));
        ccid_send(command, &[]);
        assert!(!pending(usb_wire::EP_CCID));
        assert_eq!(transport::scratch(|s| (s.owner, s.leases, s.clears)), held);
        let mut after = [0; SCRATCH_BYTES];
        assert!(Scratch::read(0, &mut after));
        assert_eq!(staged, after);
        hid_send(cid, hid_wire::INIT, NONCE);
        let init = hid_read(cid, hid_wire::INIT);
        assert_eq!(init.len(), 17);
        assert_eq!(&init[..8], NONCE);
        clean_scratch();
        let bytes = ccid_read_state(u8::from(command == ccid_wire::POWER_OFF));
        assert_eq!(
            bytes[0],
            if command == ccid_wire::POWER_ON {
                ccid_wire::DATA
            } else {
                ccid_wire::STATUS
            }
        );
        assert_eq!(
            bytes.len() > ccid_wire::HEADER,
            command == ccid_wire::POWER_ON
        );
        advance(LEASE_MS);
    }
    assert_eq!(out(usb_wire::EP_HID, &fragmented), 0);
    hid_poll();
    transport::scratch(|s| assert_ne!(s.owner, 0));
    ccid_send(ccid_wire::TRANSFER, SELECT_ADMIN);
    assert!(!pending(usb_wire::EP_CCID));
    transport::scratch(|s| assert_ne!(s.owner, 0));
    hid_send(cid, hid_wire::INIT, NONCE);
    let init = hid_read(cid, hid_wire::INIT);
    assert_eq!(init.len(), 17);
    assert_eq!(&init[..8], NONCE);
    clean_scratch();
    advance(LEASE_MS);
    sw(&ccid_read()[ccid_wire::HEADER..], 0x9000);
    // clientPIN protocol 1 key-agreement request with a 700-byte unknown bstr.
    // Parsing staged bytes must finish before key-agreement crypto reuses PKE.
    let mut pin = vec![6, 0xa3, 1, 1, 2, 2, 0x18, 0x7f, 0x59, 2, 0xbc];
    pin.extend([0xa5; 700]);
    ccid_apdu(VERIFY, 0x9000);
    hid_send(cid, hid_wire::CBOR, &pin);
    let bytes = hid_read(cid, hid_wire::CBOR);
    assert!(bytes.len() > 64 && bytes[0] == 0);
    clean_scratch();
    advance(LEASE_MS);
    ccid_apdu(SELECT_ADMIN, 0x9000);
    ccid_apdu(QUERY, 0x63c3);
    // Extended FIDO input, P1=80 and Le=0000. CCID releases staged RX before IN.
    let mut extended = vec![0x80, 0x10, 0x80, 0, 0];
    extended.extend_from_slice(&(pin.len() as u16).to_be_bytes());
    extended.extend_from_slice(&pin);
    extended.extend_from_slice(&[0, 0]);
    ccid_apdu(SELECT_FIDO, 0x9000);
    ccid_send(ccid_wire::TRANSFER, &extended);
    clean_scratch();
    let bytes = ccid_read();
    sw(&bytes[ccid_wire::HEADER..], 0x9000);
    assert!(bytes.len() > 76 && bytes[10] == 0);
    let partial = ccid_request(ccid_wire::TRANSFER, &extended, next_sequence());
    assert_eq!(out(usb_wire::EP_CCID, &partial[..PACKET_BYTES]), 0);
    ccid_poll();
    transport::scratch(|s| assert_ne!(s.owner, 0));
    setup(0, usb_wire::SET_CONFIGURATION, 0, 0, 0);
    status();
    loops();
    clean_scratch();
    setup(0, usb_wire::SET_CONFIGURATION, 1, 0, 0);
    status();
    loops();
    ccid_send(ccid_wire::POWER_ON, &[]);
    ccid_read();
    ccid_apdu(SELECT_FIDO, 0x9000);
    ccid_send(ccid_wire::TRANSFER, &extended);
    let bytes = ccid_read();
    sw(&bytes[ccid_wire::HEADER..], 0x9000);
    assert!(bytes.len() > 76 && bytes[10] == 0);
    clean_scratch();
    advance(LEASE_MS);
    hw(|h| {
        h.presence_cid = cid;
        h.presence_stage = 1;
    });
    hid_send(cid, hid_wire::CBOR, &[0x0b]);
    assert_eq!(hw(|h| h.presence_stage), 0);
    assert_eq!(hid_read(cid, hid_wire::CBOR), [0x2d]);
    hw(|h| h.sequence = 0x39);
    let bytes = ccid_read();
    assert!(bytes.len() > ccid_wire::HEADER);
    assert_eq!(bytes[0], ccid_wire::DATA);
}
