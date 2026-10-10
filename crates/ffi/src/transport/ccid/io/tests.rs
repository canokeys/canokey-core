// SPDX-License-Identifier: Apache-2.0
//! Asynchronous controller substitute for the real CCID facade and core.
#![allow(dead_code)] // Other feature profiles compile the substitute without this scenario.
use super::*;
use canokey_protocol::ccid::{DATA as DATA_BLOCK, POWER_ON, TRANSFER};

const EXTENSION_INTERVAL: u16 = 500;
// CCID headers: slot 0, sequence 0x56/0x57, body length in little endian.
const POWER: [u8; 10] = [POWER_ON, 0, 0, 0, 0, 0, 0x56, 0, 0, 0];
// XfrBlock carrying an empty-AID SELECT APDU.
const SELECT: [u8; 15] = [TRANSFER, 5, 0, 0, 0, 0, 0x57, 0, 0, 0, 0, 0xa4, 4, 0, 0];
// DataBlock time extension, sequence 0x56, multiplier 1.
const EXTENSION: [u8; 10] = [DATA_BLOCK, 0, 0, 0, 0, 0, 0x56, 0x80, 1, 0];

struct Controller {
    configured: bool,
    busy: bool,
    zlp: bool,
    now: u32,
    masked: u32,
    tx: *const u8,
    length: usize,
    saved: [u8; 300],
    submissions: usize,
    timer: Option<unsafe extern "C" fn()>,
    interval: u16,
    reset_on_lock: bool,
    fail: bool,
}
static mut CONTROLLER: Controller = Controller {
    configured: false,
    busy: false,
    zlp: false,
    now: 0,
    masked: 0,
    tx: core::ptr::null(),
    length: 0,
    saved: [0; 300],
    submissions: 0,
    timer: None,
    interval: 0,
    reset_on_lock: false,
    fail: false,
};

// One serialized test owns these singleton states, like the firmware main loop.
fn controller() -> &'static mut Controller {
    unsafe { &mut *core::ptr::addr_of_mut!(CONTROLLER) }
}
fn hardware_reset() {
    {
        let c = controller();
        c.tx = core::ptr::null();
        c.length = 0;
        c.configured = false;
        c.busy = false;
        c.zlp = false;
    }
    unsafe { ck_ccid_packet_reset() };
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
        hardware_reset();
    }
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
pub(crate) unsafe fn ck_usb_configured() -> u8 {
    u8::from(controller().configured)
}
pub(crate) unsafe fn ck_usb_tx_idle(ep: u8) -> u8 {
    assert_eq!(ep, EP_CCID_IN);
    u8::from(!controller().busy)
}
pub(crate) unsafe fn ck_usb_receive(ep: u8) {
    assert_eq!(ep, EP_CCID);
    assert_ne!(controller().masked, 0);
}
pub(crate) unsafe fn ck_usb_submit(ep: u8, bytes: *const u8, length: u16, zlp: u8) -> i32 {
    assert_eq!(ep, EP_CCID_IN);
    let c = controller();
    assert_ne!(c.masked, 0);
    let length = usize::from(length);
    assert!(length <= c.saved.len());
    if !c.configured || c.fail {
        return -1;
    }
    if c.busy {
        return 0;
    }
    c.busy = true;
    c.zlp = zlp != 0;
    c.tx = bytes;
    c.length = length;
    if length != 0 {
        c.saved[..length].copy_from_slice(unsafe { core::slice::from_raw_parts(bytes, length) });
    }
    c.submissions += 1;
    1
}
fn complete() {
    let c = controller();
    if c.length != 0 {
        assert_eq!(
            unsafe { core::slice::from_raw_parts(c.tx, c.length) },
            &c.saved[..c.length]
        );
    }
    c.tx = core::ptr::null();
    c.length = 0;
    if c.zlp {
        c.zlp = false;
    } else {
        c.busy = false;
    }
}
fn fire() {
    let callback = {
        let c = controller();
        assert_eq!(c.interval, EXTENSION_INTERVAL);
        c.now += u32::from(EXTENSION_INTERVAL);
        c.masked = 1;
        c.timer.take().unwrap()
    };
    unsafe { callback() };
    assert_eq!(controller().masked, 1);
    controller().masked = 0;
}
fn packet(bytes: &[u8]) {
    assert_eq!(unsafe { ck_ccid_io_pending() }, 0);
    assert!(bytes.len() <= 64);
    controller().masked = 1;
    let result = unsafe { ck_ccid_packet_out(bytes.as_ptr(), bytes.len() as u16) };
    controller().masked = 0;
    assert_eq!(result, u8::from(bytes.is_empty()));
}
fn configure() {
    hardware_reset();
    controller().configured = true;
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
}
fn normal_exchange() {
    packet(&POWER[..3]);
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
    packet(&POWER[3..]);
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
    {
        let c = controller();
        assert_eq!(c.length, 27);
        assert_eq!((c.saved[0], c.saved[6], c.saved[7]), (DATA_BLOCK, 0x56, 0));
    }
    packet(&SELECT);
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
    assert_ne!(unsafe { ck_ccid_io_pending() }, 0);
    complete();
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
    assert_eq!(unsafe { ck_ccid_io_pending() }, 0);
    {
        let c = controller();
        assert_eq!(c.length, 12);
        assert_eq!((c.saved[0], c.saved[6], c.saved[7]), (DATA_BLOCK, 0x57, 0));
        assert!(c.timer.is_none());
    }
    complete();
    unsafe { crate::transport::ccid::poll::<crate::platform::Native>() };
}

#[cfg(not(any(
    feature = "admin",
    feature = "pass",
    feature = "oath",
    feature = "ctap",
    feature = "piv",
    feature = "openpgp",
    feature = "ndef"
)))]
#[test]
fn ccid_controller_leases_timer_reset_and_fragmentation() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    unsafe {
        configure();
        normal_exchange();
        packet(&[]);
        crate::transport::ccid::poll::<crate::platform::Native>();
        assert_ne!(ck_ccid_io_idle(), 0);
        let epoch = ck_ccid_io_generation();
        ck_ccid_io_arm(
            epoch,
            EXTENSION.as_ptr(),
            EXTENSION.len() as u8,
            EXTENSION_INTERVAL,
        );
        assert!(controller().timer.is_some());
        assert_ne!(ck_ccid_io_live(), 0);
        fire();
        assert_eq!(controller().length, EXTENSION.len());
        assert_eq!(&controller().saved[..EXTENSION.len()], &EXTENSION);
        let sent = controller().submissions;
        fire();
        assert_eq!(controller().submissions, sent);
        let wrong = [0xff; 10];
        ck_ccid_io_arm(epoch, wrong.as_ptr(), wrong.len() as u8, EXTENSION_INTERVAL);
        assert_eq!(
            core::slice::from_raw_parts(controller().tx, EXTENSION.len()),
            &EXTENSION
        );
        ck_ccid_io_disarm();
        assert!(controller().timer.is_none());
        assert_eq!(ck_ccid_io_live(), 0);
        let mut final_packet = [0; 64];
        final_packet[0] = DATA_BLOCK;
        assert_eq!(ck_ccid_io_submit(epoch, final_packet.as_ptr(), 64, 1), 0);
        complete();
        assert_eq!(ck_ccid_io_submit(epoch, final_packet.as_ptr(), 64, 1), 1);
        assert_eq!(ck_ccid_io_idle(), 0);
        complete();
        assert_eq!(ck_ccid_io_idle(), 0);
        assert_eq!(controller().length, 0);
        complete();
        assert_ne!(ck_ccid_io_idle(), 0);
        controller().masked = 1;
        assert_eq!(ck_ccid_io_submit(epoch, final_packet.as_ptr(), 12, 0), 1);
        assert_eq!(controller().masked, 1);
        controller().masked = 0;
        complete();
        controller().fail = true;
        assert_eq!(ck_ccid_io_submit(epoch, final_packet.as_ptr(), 12, 0), -1);
        assert_ne!(ck_ccid_io_idle(), 0);
        controller().fail = false;
        controller().reset_on_lock = true;
        assert_eq!(ck_ccid_io_submit(epoch, final_packet.as_ptr(), 12, 0), -1);
        assert!(controller().timer.is_none());
        assert_ne!(ck_ccid_io_generation(), epoch);
        configure();
        normal_exchange();
        hardware_reset();
        controller().configured = true;
        packet(&POWER);
        crate::transport::ccid::poll::<crate::platform::Native>();
        assert_ne!(ck_ccid_io_pending(), 0);
        crate::transport::ccid::poll::<crate::platform::Native>();
        assert_eq!(controller().length, 27);
        complete();
        crate::transport::ccid::poll::<crate::platform::Native>();
        packet(&POWER);
        crate::transport::ccid::poll::<crate::platform::Native>();
        controller().now += 2000;
        crate::transport::ccid::poll::<crate::platform::Native>();
        assert_eq!(ck_ccid_io_idle(), 0);
        complete();
        crate::transport::ccid::poll::<crate::platform::Native>();
        let epoch = ck_ccid_io_generation();
        configure();
        packet(&POWER);
        let mut out = [0; 64];
        let mut tick = 0;
        assert_eq!(ck_ccid_io_take(epoch, out.as_mut_ptr(), &mut tick), -1);
        assert_ne!(ck_ccid_io_pending(), 0);
        crate::transport::ccid::poll::<crate::platform::Native>();
        complete();
        crate::transport::ccid::poll::<crate::platform::Native>();
    }
}
