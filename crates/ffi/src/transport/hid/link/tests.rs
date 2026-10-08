// SPDX-License-Identifier: Apache-2.0
//! Link/mailbox behavior; the core integration suite covers CTAP execution.
use super::*;
use crate::transport::hid::io::{ck_hid_packet_reset, out_event, rx_can_accept};
use canokey_protocol::usb::{DATA_PACKET_BYTES, EP_HID, EP_HID_IN};
const CHANNEL: u32 = 0x12345678;
// Initial PING on CHANNEL, big-endian body length 1, payload 0xab.
const PACKET: [u8; DATA_PACKET_BYTES] = {
    let mut packet = [0; DATA_PACKET_BYTES];
    packet[0] = 0x12;
    packet[1] = 0x34;
    packet[2] = 0x56;
    packet[3] = 0x78;
    packet[4] = wire::PING;
    packet[6] = 1;
    packet[7] = 0xab;
    packet
};
struct Controller {
    now: u32,
    masked: u32,
    reset_on_lock: bool,
    received: usize,
    resets: usize,
    sent: usize,
    inject: u8,
    reset_during_poll: bool,
    respond: bool,
    idle: bool,
    in_flight: *const u8,
}
static mut CONTROLLER: Controller = Controller {
    now: 0,
    masked: 0,
    reset_on_lock: false,
    received: 0,
    resets: 0,
    sent: 0,
    inject: 0,
    reset_during_poll: false,
    respond: false,
    idle: true,
    in_flight: core::ptr::null(),
};
fn controller() -> &'static mut Controller {
    unsafe { &mut *core::ptr::addr_of_mut!(CONTROLLER) }
}
fn in_flight() -> &'static [u8; DATA_PACKET_BYTES] {
    unsafe { &*controller().in_flight.cast::<[u8; DATA_PACKET_BYTES]>() }
}
pub(crate) unsafe fn device_get_tick() -> u32 {
    controller().now
}
pub(crate) unsafe fn device_delay(ms: i32) {
    controller().now += ms as u32;
}
pub(crate) unsafe fn ck_hid_reset<P: crate::composition::Provider>() {
    controller().resets += 1;
}
pub(crate) unsafe fn ck_hid_poll<P: crate::composition::Provider>(
    input: *const [u8; DATA_PACKET_BYTES],
    tick: u32,
    now: u32,
    out: *mut [u8; DATA_PACKET_BYTES],
) -> u8 {
    assert_eq!(now, controller().now);
    if !input.is_null() {
        assert!(tick <= now);
        assert_eq!(unsafe { &*input }, &PACKET);
        if controller().inject == 2 {
            controller().inject = 0;
            let mut next = PACKET;
            next[7] ^= 0xff;
            assert_ne!(unsafe { out_event(next.as_ptr()) }, 0);
            assert_eq!(unsafe { &*input }, &PACKET);
        }
        controller().received += 1;
    }
    if controller().inject != 0 {
        controller().inject = 0;
        assert!(input.is_null());
        assert_ne!(unsafe { out_event(PACKET.as_ptr()) }, 0);
    }
    if controller().reset_during_poll {
        controller().reset_during_poll = false;
        unsafe { ck_hid_packet_reset() };
    }
    if controller().respond {
        controller().respond = false;
        unsafe { out.write([0x5a; DATA_PACKET_BYTES]) };
        return 3;
    }
    0
}
pub(crate) unsafe fn ck_usb_dcd_lock() -> u32 {
    let (prior, reset) = {
        let c = controller();
        let prior = c.masked;
        c.masked = 1;
        let reset = c.reset_on_lock;
        c.reset_on_lock = false;
        (prior, reset)
    };
    if reset {
        unsafe { ck_hid_packet_reset() };
    }
    prior
}
pub(crate) unsafe fn ck_usb_dcd_unlock(prior: u32) {
    controller().masked = prior;
}
pub(crate) unsafe fn ck_usb_configured() -> u8 {
    1
}
pub(crate) unsafe fn ck_usb_tx_idle(ep: u8) -> u8 {
    assert_eq!(ep, EP_HID_IN);
    u8::from(controller().idle)
}
pub(crate) unsafe fn ck_usb_submit(ep: u8, out: *const u8, length: u16, zlp: u8) -> i32 {
    assert_eq!(ep, EP_HID_IN);
    assert_eq!(zlp, 0);
    assert_eq!(usize::from(length), DATA_PACKET_BYTES);
    let c = controller();
    assert!(c.idle);
    assert_ne!(c.masked, 0);
    c.idle = false;
    c.in_flight = out;
    c.sent += 1;
    1
}
pub(crate) unsafe fn ck_usb_receive(ep: u8) {
    assert_eq!(ep, EP_HID);
    assert_ne!(controller().masked, 0);
}
fn packet(bytes: &[u8; DATA_PACKET_BYTES]) {
    assert_ne!(unsafe { out_event(bytes.as_ptr()) }, 0);
}
fn poll() {
    unsafe { CTAPHID_Loop(0) };
}
fn empty_mailbox() -> bool {
    unsafe { rx_can_accept() != 0 }
}

#[test]
fn hid_link_interrupt_leases_progress_and_cancellation() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    unsafe {
        ck_hid_packet_reset();
        controller().inject = 1;
        poll();
        assert_eq!(controller().received, 0);
        assert!(!empty_mailbox());
        poll();
        assert_eq!(controller().received, 1);
        assert!(empty_mailbox());
        packet(&PACKET);
        controller().respond = true;
        poll();
        assert_eq!(controller().sent, 1);
        assert_ne!(ck_hid_busy(), 0);
        packet(&PACKET);
        controller().now = TX_TIMEOUT_MS;
        let before = controller().resets;
        poll();
        assert_eq!(controller().resets, before + 1);
        assert_eq!(ck_hid_busy(), 0);
        assert!(!controller().idle);
        assert_eq!(in_flight(), &[0x5a; DATA_PACKET_BYTES]);
        poll();
        assert_eq!(controller().received, 2);
        assert_eq!(controller().resets, before + 1);
        controller().idle = true;
        poll();
        assert_eq!(controller().received, 3);
        packet(&PACKET);
        controller().respond = true;
        controller().reset_during_poll = true;
        poll();
        assert_eq!(controller().sent, 1);
        poll();
        assert!(empty_mailbox());
        assert_eq!(ck_hid_busy(), 0);
        packet(&PACKET);
        controller().inject = 2;
        poll();
        assert!(!empty_mailbox());
        ck_hid_packet_reset();
        poll();
        ck_hid_execution_begin(CHANNEL);
        ck_hid_keepalive(1);
        assert_ne!(ck_hid_executing(), 0);
        assert_ne!(ck_hid_busy(), 0);
        assert_ne!(ck_hid_progress(), 0);
        assert_eq!(&in_flight()[..4], &CHANNEL.to_be_bytes());
        assert_eq!(
            (in_flight()[4], in_flight()[6], in_flight()[7]),
            (wire::KEEPALIVE, 1, wire::STATUS_UPNEEDED)
        );
        let mut command = [0; DATA_PACKET_BYTES];
        wire::header(&mut command, CHANNEL, wire::CANCEL, 0);
        packet(&command);
        assert_eq!(ck_hid_progress(), 0);
        assert_eq!(
            (in_flight()[4], in_flight()[7]),
            (wire::KEEPALIVE, wire::STATUS_UPNEEDED)
        );
        controller().idle = true;
        ck_hid_execution_end();
        assert_eq!(ck_hid_executing(), 0);
        ck_hid_execution_begin(CHANNEL);
        command[0] = 0x87; // Foreign channel with the same low 24 bits.
        packet(&command);
        assert_ne!(ck_hid_progress(), 0);
        assert_eq!(
            (in_flight()[0], in_flight()[4], in_flight()[7]),
            (0x87, wire::ERROR, Error::Busy as u8)
        );
        controller().idle = true;
        wire::header(&mut command, CHANNEL, wire::INIT, 8);
        packet(&command);
        assert_eq!(ck_hid_progress(), 0);
        assert!(!empty_mailbox());
        ck_hid_execution_end();
        ck_hid_packet_reset();
        poll();
        ck_hid_execution_begin(CHANNEL);
        assert_ne!(ck_hid_progress(), 0);
        ck_hid_execution_end();
        assert!(!controller().idle);
        assert_eq!(
            (in_flight()[4], in_flight()[7]),
            (wire::KEEPALIVE, wire::STATUS_PROCESSING)
        );
        assert_eq!(ck_hid_executing(), 0);
        controller().idle = true;
        ck_hid_packet_reset();
        poll();
        packet(&PACKET);
        controller().respond = true;
        poll();
        controller().idle = true;
        poll();
        assert_ne!(ck_hid_busy(), 0);
        controller().now += SESSION_IDLE_MS - 1;
        assert_ne!(ck_hid_busy(), 0);
        controller().now += 1;
        assert_eq!(ck_hid_busy(), 0);
        packet(&PACKET);
        let sent = controller().sent;
        controller().reset_on_lock = true;
        controller().respond = true;
        poll();
        assert_eq!(controller().sent, sent);
        assert_eq!(controller().masked, 0);
        poll();
        ck_hid_packet_reset();
        let received = controller().received;
        packet(&PACKET);
        poll();
        assert_eq!(controller().received, received + 1);
        controller().idle = true;
        ck_hid_packet_reset();
        poll();
        let received = controller().received;
        let resets = controller().resets;
        let mut competing = [0; DATA_PACKET_BYTES];
        wire::header(&mut competing, CHANNEL, wire::CBOR, 1)[0] = 4;
        packet(&competing);
        ck_hid_foreign_progress();
        assert!(!controller().idle);
        assert_eq!(
            (in_flight()[4], in_flight()[7]),
            (wire::ERROR, Error::Busy as u8)
        );
        assert_eq!(&in_flight()[..4], &competing[..4]);
        assert_eq!(controller().received, received);
        assert_eq!(controller().resets, resets);
        assert_eq!(ck_hid_executing(), 0);
        let saved = *in_flight();
        wire::header(&mut competing, CHANNEL, wire::INIT, 8);
        packet(&competing);
        ck_hid_foreign_progress();
        assert_eq!(in_flight(), &saved);
        assert!(!empty_mailbox());
        controller().idle = true;
        ck_hid_foreign_progress();
        assert_eq!(in_flight()[7], Error::Busy as u8);
        assert!(empty_mailbox());
        controller().idle = true;
        wire::header(&mut competing, CHANNEL, wire::CANCEL, 0);
        let sent = controller().sent;
        packet(&competing);
        ck_hid_foreign_progress();
        assert_eq!(controller().sent, sent);
        assert!(empty_mailbox());
        wire::header(&mut competing, 0, wire::PING, 0);
        packet(&competing);
        ck_hid_foreign_progress();
        assert_eq!(in_flight()[7], Error::Channel as u8);
        controller().idle = true;
        ck_hid_packet_reset();
        ck_hid_foreign_progress();
        assert_eq!(controller().resets, resets);
        poll();
        controller().masked = 1;
        controller().respond = true;
        poll();
        assert_eq!(controller().masked, 1);
    }
}
