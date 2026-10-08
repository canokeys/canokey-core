// SPDX-License-Identifier: Apache-2.0
//! Actual USB/mailbox/handoff code with asynchronous hardware FIFOs.
use super::*;
use crate::transport::ccid::io::*;

const ADDRESS: u8 = 17;
const EXTENSION_INTERVAL: u16 = 500;
const CONTROL_IN_EP: u8 = 0x80;
const DEVICE_DESCRIPTOR: u16 = 0x0100;
const CONFIGURATION_DESCRIPTOR: u16 = 0x0200;
#[cfg(any(feature = "usb-hid", feature = "usb-keyboard"))]
const REPORT_DESCRIPTOR: u16 = 0x2200;
// Empty-AID SELECT, the short APDU used by the WebUSB policy substitute.
#[cfg(feature = "usb-webusb")]
const SELECT: [u8; 5] = [0, 0xa4, 4, 0, 0];

struct Controller {
    masked: u32,
    now: u32,
    address: u8,
    ready: bool,
    opened: [bool; 8],
    halted: [bool; 8],
    pending: [bool; 4],
    packets: [[u8; 64]; 4],
    lengths: [usize; 4],
    submissions: [usize; 4],
    timer: Option<unsafe extern "C" fn()>,
    interval: u16,
    fail: bool,
    #[cfg(feature = "usb-hid")]
    foreign_progress: usize,
}
static mut CONTROLLER: Controller = Controller {
    masked: 0,
    now: 0,
    address: 0,
    ready: false,
    opened: [false; 8],
    halted: [false; 8],
    pending: [false; 4],
    packets: [[0; 64]; 4],
    lengths: [0; 4],
    submissions: [0; 4],
    timer: None,
    interval: 0,
    fail: false,
    #[cfg(feature = "usb-hid")]
    foreign_progress: 0,
};
fn controller() -> &'static mut Controller {
    unsafe { &mut *core::ptr::addr_of_mut!(CONTROLLER) }
}
fn endpoint(ep: u8) -> usize {
    usize::from(ep & ENDPOINT_NUMBER_MASK)
}
fn direction(ep: u8) -> usize {
    endpoint(ep) * 2 + usize::from(ep >> 7)
}
pub(crate) unsafe fn ck_usb_dcd_lock() -> u32 {
    let c = controller();
    let prior = c.masked;
    c.masked = 1;
    prior
}
pub(crate) unsafe fn ck_usb_dcd_unlock(prior: u32) {
    controller().masked = prior;
}
pub(crate) unsafe fn device_get_tick() -> u32 {
    controller().now
}
pub(crate) unsafe fn device_set_timeout(next: Option<unsafe extern "C" fn()>, ms: u16) {
    let c = controller();
    c.timer = next;
    c.interval = ms;
}
pub(crate) unsafe fn ck_usb_dcd_start() {
    assert_ne!(controller().masked, 0);
}
pub(crate) unsafe fn ck_usb_dcd_enable_irq() {
    assert_ne!(controller().masked, 0);
}
pub(crate) unsafe fn ck_usb_dcd_stop() {
    assert_ne!(controller().masked, 0);
}
pub(crate) unsafe fn ck_usb_dcd_open(ep: u8) {
    let c = controller();
    assert_ne!(c.masked, 0);
    c.opened[direction(ep)] = true;
    c.halted[direction(ep)] = false;
}
pub(crate) unsafe fn ck_usb_dcd_close(ep: u8) {
    let c = controller();
    assert_ne!(c.masked, 0);
    c.opened[direction(ep)] = false;
    if ep & 0x80 != 0 {
        c.pending[endpoint(ep)] = false;
    }
}
pub(crate) unsafe fn ck_usb_dcd_stall(ep: u8, halt: u8) {
    let c = controller();
    assert_ne!(c.masked, 0);
    c.halted[direction(ep)] = halt != 0;
}
pub(crate) unsafe fn ck_usb_dcd_address(address: u8) {
    assert_ne!(controller().masked, 0);
    controller().address = address;
}
pub(crate) unsafe fn ck_usb_dcd_ready(ready: u8) {
    assert_ne!(controller().masked, 0);
    controller().ready = ready != 0;
}
pub(crate) unsafe fn ck_usb_dcd_receive(ep: u8) {
    let c = controller();
    assert_ne!(c.masked, 0);
    assert!(c.opened[direction(ep)]);
}
pub(crate) unsafe fn ck_usb_dcd_write(ep: u8, bytes: *const u8, length: u16) -> u8 {
    let c = controller();
    let n = usize::from(length);
    let ix = endpoint(ep);
    assert_ne!(c.masked, 0);
    assert!(c.opened[direction(ep)] && ep & 0x80 != 0 && !c.pending[ix]);
    assert!(
        n <= if ix == 0 {
            EP0_PACKET_BYTES
        } else {
            DATA_PACKET_BYTES
        }
    );
    if c.fail {
        c.fail = false;
        return 0;
    }
    if n != 0 {
        c.packets[ix][..n].copy_from_slice(unsafe { core::slice::from_raw_parts(bytes, n) });
    }
    c.lengths[ix] = n;
    c.pending[ix] = true;
    c.submissions[ix] += 1;
    1
}
fn complete(ep: u8) {
    assert!(controller().pending[endpoint(ep)]);
    controller().pending[endpoint(ep)] = false;
    unsafe { ck_usb_in(ep) };
}
fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) {
    let mut bytes = [kind, request, 0, 0, 0, 0, 0, 0];
    bytes[2..4].copy_from_slice(&value.to_le_bytes());
    bytes[4..6].copy_from_slice(&index.to_le_bytes());
    bytes[6..8].copy_from_slice(&length.to_le_bytes());
    unsafe { ck_usb_setup(bytes.as_ptr(), bytes.len() as u16) };
}
fn status() {
    assert!(controller().pending[0]);
    assert_eq!(controller().lengths[0], 0);
    complete(CONTROL_IN_EP);
}
fn read_control(output: &mut [u8]) -> usize {
    let mut n = 0;
    while controller().pending[0] {
        {
            let c = controller();
            let end = n + c.lengths[0];
            output[n..end].copy_from_slice(&c.packets[0][..c.lengths[0]]);
            n = end;
        }
        complete(CONTROL_IN_EP);
    }
    assert_eq!(unsafe { ck_usb_out(0, core::ptr::null(), 0) }, 1);
    n
}
fn bus_reset() {
    {
        let c = controller();
        c.pending.fill(false);
        c.opened.fill(false);
        c.halted.fill(false);
        c.opened[0] = true;
        c.opened[1] = true;
        c.address = 0;
    }
    unsafe { ck_usb_bus_reset() };
}
fn configure() {
    unsafe { init() };
    assert_ne!(controller().masked, 0);
    assert_eq!(controller().address, 0);
    assert!(!controller().ready);
    setup(0, SET_ADDRESS, u16::from(ADDRESS), 0, 0);
    assert_eq!(controller().address, ADDRESS);
    status();
    assert_eq!(controller().address, ADDRESS);
    setup(0, SET_CONFIGURATION, 1, 0, 0);
    assert!(controller().ready);
    assert_ne!(unsafe { ck_usb_configured() }, 0);
    status();
}
#[cfg(feature = "usb-hid")]
pub(crate) unsafe fn ck_hid_executing() -> u8 {
    0
}
#[cfg(feature = "usb-hid")]
pub(crate) unsafe fn ck_hid_progress() -> u8 {
    0
}
#[cfg(feature = "usb-hid")]
pub(crate) unsafe fn ck_hid_foreign_progress() {
    controller().foreign_progress += 1;
}
#[cfg(feature = "usb-hid")]
pub(crate) unsafe fn presence_progress() {
    unreachable!("HID execution is covered by the core USB-session suite");
}

#[cfg(feature = "usb-webusb")]
mod web;
#[cfg(all(feature = "usb-webusb", feature = "usb-hid"))]
pub(crate) use web::ck_hid_busy;
#[cfg(feature = "usb-webusb")]
pub(crate) use web::{can_preempt, ck_ccid_idle, ck_core_exchange, ck_core_reset};

#[test]
fn usb_controller_control_endpoints_mailboxes_and_reset() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    unsafe {
        controller().masked = 1;
        configure();
        let mut bytes = [0; 256];
        let packet = [0xa5; 64]; // Retained interrupt OUT data, including its entire tail.
        setup(0x80, GET_DESCRIPTOR, DEVICE_DESCRIPTOR, 0, 255);
        assert_eq!(read_control(&mut bytes), 18);
        assert_eq!((bytes[7], bytes[8], bytes[9]), (16, 0xa0, 0x20));
        let bcd = option_env!("CANOKEY_USB_BCD_DEVICE").unwrap_or("0x0100");
        let bcd = match bcd.strip_prefix("0x") {
            Some(hex) => u16::from_str_radix(hex, 16).unwrap(),
            None => bcd.parse().unwrap(),
        };
        assert_eq!(u16::from_le_bytes([bytes[12], bytes[13]]), bcd);
        setup(0x80, GET_DESCRIPTOR, CONFIGURATION_DESCRIPTOR, 0, 255);
        assert_eq!(
            read_control(&mut bytes),
            86 + 32 * (usize::from(INTERFACES.hid) + usize::from(INTERFACES.keyboard))
                + 9 * usize::from(INTERFACES.webusb)
        );
        assert_eq!(
            bytes[4],
            1 + u8::from(INTERFACES.hid)
                + u8::from(INTERFACES.keyboard)
                + u8::from(INTERFACES.webusb)
        );
        setup(0x80, GET_DESCRIPTOR, CONFIGURATION_DESCRIPTOR, 0, 9);
        assert_eq!(read_control(&mut bytes), 9);
        // String descriptor index 2, US English language ID.
        setup(0x80, GET_DESCRIPTOR, 0x0302, 0x0409, 255);
        assert_eq!(read_control(&mut bytes), 36);
        assert_eq!(bytes[1], 3);
        setup(0x80, GET_DESCRIPTOR, CONFIGURATION_DESCRIPTOR, 0, 255);
        assert_eq!(controller().lengths[0], 16);
        setup(0x80, GET_CONFIGURATION, 0, 0, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], 1);
        setup(0x80, GET_DESCRIPTOR, CONFIGURATION_DESCRIPTOR, 0, 255);
        let sent = controller().submissions[0];
        ck_usb_out(0, core::ptr::null(), 0);
        assert!(!controller().pending[0]);
        ck_usb_in(CONTROL_IN_EP);
        assert_eq!(controller().submissions[0], sent);
        // Invalid endpoint index high byte must stall both EP0 directions.
        setup(0x82, GET_STATUS, 0, 0x0183, 2);
        assert!(controller().halted[0] && controller().halted[1]);
        setup(0x80, GET_CONFIGURATION, 0, 0, 1);
        assert!(!controller().halted[0] && !controller().halted[1]);
        assert_eq!(read_control(&mut bytes), 1);
        setup(2, SET_FEATURE, 0, u16::from(EP_CCID_IN), 0);
        status();
        assert!(controller().halted[direction(EP_CCID_IN)]);
        setup(0x82, GET_STATUS, 0, u16::from(EP_CCID_IN), 2);
        assert_eq!(read_control(&mut bytes), 2);
        assert_eq!(bytes[0], 1);
        assert_eq!(ck_usb_submit(EP_CCID_IN, packet.as_ptr(), 64, 0), 0);
        setup(2, CLEAR_FEATURE, 0, u16::from(EP_CCID_IN), 0);
        status();
        assert!(!controller().halted[direction(EP_CCID_IN)]);
        ck_usb_suspend();
        assert_ne!(ck_usb_configured(), 0);
        assert_eq!(ck_usb_submit(EP_CCID_IN, packet.as_ptr(), 64, 0), 0);
        ck_usb_resume();
        assert_ne!(ck_usb_configured(), 0);
        let payload: [u8; 128] = core::array::from_fn(|i| i as u8);
        assert_eq!(ck_usb_submit(EP_CCID_IN, payload.as_ptr(), 128, 1), 1);
        assert_eq!(ck_usb_tx_idle(EP_CCID_IN), 0);
        assert_eq!(controller().lengths[3], 64);
        assert_eq!(&controller().packets[3], &payload[..64]);
        assert_eq!(ck_usb_submit(EP_CCID_IN, payload.as_ptr(), 1, 0), 0);
        complete(EP_CCID_IN);
        assert_eq!(controller().lengths[3], 64);
        assert_eq!(&controller().packets[3], &payload[64..]);
        complete(EP_CCID_IN);
        assert_eq!(controller().lengths[3], 0);
        assert_eq!(ck_usb_tx_idle(EP_CCID_IN), 0);
        complete(EP_CCID_IN);
        assert_ne!(ck_usb_tx_idle(EP_CCID_IN), 0);
        controller().fail = true;
        assert_eq!(ck_usb_submit(EP_CCID_IN, packet.as_ptr(), 64, 0), -1);
        assert_ne!(ck_usb_tx_idle(EP_CCID_IN), 0);
        let mut generation = ck_ccid_io_generation();
        let mut tick = 0;
        assert_eq!(ck_usb_out(EP_CCID, packet.as_ptr(), 64), 0);
        assert_ne!(ck_ccid_io_pending(), 0);
        assert_eq!(
            ck_ccid_io_take(generation, bytes.as_mut_ptr(), &mut tick),
            64
        );
        assert_eq!(&bytes[..64], &packet);
        assert_eq!(ck_ccid_io_pending(), 0);
        assert_ne!(controller().masked, 0);
        ck_ccid_io_arm(generation, packet.as_ptr(), 10, EXTENSION_INTERVAL);
        assert_eq!(controller().interval, EXTENSION_INTERVAL);
        assert!(controller().timer.is_some());
        #[cfg(feature = "usb-hid")]
        let before = controller().foreign_progress;
        assert_eq!(ck_transport_progress(), 1);
        #[cfg(feature = "usb-hid")]
        assert_eq!(controller().foreign_progress, before + 1);
        controller().now += u32::from(EXTENSION_INTERVAL);
        let callback = controller().timer.unwrap();
        callback();
        assert!(controller().pending[3]);
        assert_eq!(controller().lengths[3], 10);
        complete(EP_CCID_IN);
        #[cfg(feature = "usb-hid")]
        {
            use crate::transport::hid::io::*;
            setup(0x81, GET_DESCRIPTOR, REPORT_DESCRIPTOR, 0, 255);
            assert_eq!(read_control(&mut bytes), 34);
            assert_eq!(bytes[0], 6);
            let epoch = ck_hid_io_epoch();
            ck_hid_io_ack_reset(epoch);
            assert_eq!(ck_usb_out(EP_HID, packet.as_ptr(), 63), 1);
            assert_eq!(ck_hid_io_peek(bytes.as_mut_ptr(), 64, &mut tick, epoch), 0);
            assert_eq!(ck_usb_out(EP_HID, packet.as_ptr(), 64), 0);
            assert_ne!(ck_hid_io_peek(bytes.as_mut_ptr(), 64, &mut tick, epoch), 0);
            assert_eq!(&bytes[..64], &packet);
            ck_hid_io_consume(epoch);
            ck_usb_receive(EP_HID);
        }
        #[cfg(feature = "usb-keyboard")]
        {
            let interface = 1 + u16::from(INTERFACES.hid) + u16::from(INTERFACES.webusb);
            setup(0x81, GET_DESCRIPTOR, REPORT_DESCRIPTOR, interface, 255);
            assert_eq!(read_control(&mut bytes), 87);
            assert_eq!(bytes[0], 5);
            // HID SET_IDLE/GET_IDLE and two-byte output LED report ID 1.
            setup(0x21, 10, 0x0701, interface, 0);
            status();
            setup(0xa1, 2, 1, interface, 1);
            assert_eq!(read_control(&mut bytes), 1);
            assert_eq!(bytes[0], 7);
            setup(0x21, 9, 0x0201, interface, 2);
            assert!(!controller().pending[0]);
            let led = [1, 7];
            assert_eq!(ck_usb_out(0, led.as_ptr(), 2), 1);
            status();
            setup(0x21, 9, 0x0201, interface, 2);
            assert_eq!(ck_usb_out(0, led.as_ptr(), 1), 1);
            assert!(controller().halted[1]);
        }
        #[cfg(feature = "usb-hid")]
        {
            use crate::transport::hid::io::ck_hid_io_epoch;
            let epoch = ck_hid_io_epoch();
            setup(1, SET_INTERFACE, 0, 0, 0);
            status();
            assert_ne!(ck_hid_io_epoch(), epoch);
            assert_eq!(ck_ccid_io_generation(), generation);
            assert!(controller().timer.is_some() && controller().ready);
        }
        #[cfg(feature = "usb-webusb")]
        {
            web::scenario();
            generation = ck_ccid_io_generation();
        }
        assert_eq!(ck_ccid_io_submit(generation, payload.as_ptr(), 128, 1), 1);
        ck_ccid_io_arm(generation, packet.as_ptr(), 10, EXTENSION_INTERVAL);
        bus_reset();
        assert!(!controller().ready && controller().timer.is_none());
        assert_eq!(ck_usb_configured(), 0);
        assert_ne!(ck_ccid_io_generation(), generation);
        assert_eq!(
            ck_ccid_io_take(generation, bytes.as_mut_ptr(), &mut tick),
            -1
        );
        let sent = controller().submissions[3];
        ck_usb_in(EP_CCID_IN);
        assert_eq!(controller().submissions[3], sent);
        setup(0, SET_ADDRESS, u16::from(ADDRESS), 0, 0);
        status();
        setup(0, SET_CONFIGURATION, 1, 0, 0);
        status();
        generation = ck_ccid_io_generation();
        assert_eq!(ck_ccid_io_submit(generation, payload.as_ptr(), 128, 1), 1);
        setup(0, SET_CONFIGURATION, 0, 0, 0);
        status();
        assert!(!controller().ready && controller().timer.is_none() && !controller().pending[3]);
        assert_eq!(ck_usb_configured(), 0);
        assert_ne!(ck_ccid_io_generation(), generation);
        assert_eq!(
            ck_ccid_io_take(generation, bytes.as_mut_ptr(), &mut tick),
            -1
        );
        let sent = controller().submissions[3];
        ck_usb_in(EP_CCID_IN);
        assert_eq!(controller().submissions[3], sent);
        setup(0, SET_ADDRESS, 27, 0, 0);
        assert_eq!(controller().address, 27);
        setup(0x80, GET_STATUS, 0, 0, 2);
        assert_eq!(read_control(&mut bytes), 2);
        assert_eq!(controller().address, 27);
        setup(0, SET_CONFIGURATION, 1, 0, 0);
        status();
        assert!(controller().ready);
        ck_usb_reset();
        assert_eq!(controller().address, 0);
        assert!(!controller().ready && !controller().pending[0] && !controller().pending[3]);
        assert!(!controller().opened[2] && !controller().opened[4] && !controller().opened[6]);
        controller().masked = 0;
        deinit();
        assert_eq!(controller().masked, 0);
    }
}
