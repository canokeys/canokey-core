// SPDX-License-Identifier: Apache-2.0
//! Serialized HID link policy. IRQs access only the native mailbox, never this
//! state. Core execution may call progress, so no state borrow crosses a poll.
use canokey_protocol::ctaphid::{self as wire, Error};

unsafe extern "C" {
    fn device_get_tick() -> u32;
    fn device_delay(ms: i32);
    fn ck_hid_io_epoch() -> u32;
    fn ck_hid_io_reset_pending() -> u8;
    fn ck_hid_io_ack_reset(epoch: u32);
    fn ck_hid_io_configured() -> u8;
    fn ck_hid_io_idle() -> u8;
    fn ck_hid_io_peek(report: *mut u8, length: u8, tick: *mut u32, epoch: u32) -> u8;
    fn ck_hid_io_consume(epoch: u32);
    fn ck_hid_io_receive();
    fn ck_hid_io_send(report: *mut u8, epoch: u32) -> u8;
    fn ck_hid_reset();
    fn ck_hid_poll(input: *const u8, received: u32, now: u32, output: *mut u8) -> u8;
}
// Separate endpoint-owned buffers: progress runs while poll borrows OUTGOING.
static mut OUTGOING: [u8; 64] = [0; 64];
static mut CONTROL: [u8; 64] = [0; 64];
struct Link {
    sent_at: u32,
    session_last_used: u32,
    active: bool,
    transmitting: bool,
    session_owned: bool,
    executing_cid: u32,
    execution_epoch: u32,
    keepalive_at: u32,
    executing: bool,
    cancelled: bool,
    abandon: bool,
    keepalive_status: u8,
}
impl Link {
    const fn new() -> Self {
        Self {
            sent_at: 0,
            session_last_used: 0,
            active: false,
            transmitting: false,
            session_owned: false,
            executing_cid: 0,
            execution_epoch: 0,
            keepalive_at: 0,
            executing: false,
            cancelled: false,
            abandon: false,
            keepalive_status: 1,
        }
    }
}
static mut LINK: Link = Link::new();
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_active() -> u8 {
    unsafe { u8::from(LINK.active) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_busy() -> u8 {
    unsafe {
        u8::from(
            LINK.active
                || (LINK.session_owned
                    && device_get_tick().wrapping_sub(LINK.session_last_used) < 2000),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_executing() -> u8 {
    unsafe { u8::from(LINK.executing) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_execution_begin(cid: u32) {
    unsafe {
        LINK.executing_cid = cid;
        LINK.execution_epoch = ck_hid_io_epoch();
        LINK.executing = true;
        LINK.active = true;
        LINK.cancelled = false;
        LINK.abandon = false;
        LINK.keepalive_status = 1;
        LINK.keepalive_at = device_get_tick().wrapping_sub(100);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_keepalive(waiting: u8) {
    unsafe {
        LINK.keepalive_status = if waiting != 0 { 2 } else { 1 };
    }
}
unsafe fn send_control(cid: u32, command: u8, value: u8) {
    unsafe {
        let report = &mut *core::ptr::addr_of_mut!(CONTROL);
        wire::header(report, cid, command, 1)[0] = value;
        if ck_hid_io_send(report.as_mut_ptr(), LINK.execution_epoch) == 0 {
            LINK.abandon = true;
            return;
        }
        LINK.sent_at = device_get_tick();
        LINK.transmitting = true;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_progress() -> u8 {
    unsafe {
        if !LINK.executing || ck_hid_io_reset_pending() != 0 || ck_hid_io_configured() == 0 {
            return 0;
        }
        let mut idle = ck_hid_io_idle() != 0;
        if !idle && LINK.transmitting && device_get_tick().wrapping_sub(LINK.sent_at) >= 1000 {
            LINK.abandon = true;
        }
        // Only the initial header is needed while crypto owns the core stack.
        let mut report = [0; 7];
        let mut received = 0;
        if ck_hid_io_peek(
            report.as_mut_ptr(),
            report.len() as u8,
            &mut received,
            LINK.execution_epoch,
        ) != 0
        {
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            let length = u16::from_be_bytes([report[5], report[6]]);
            if cid == LINK.executing_cid && report[4] == wire::INIT && length == 8 {
                // Keep INIT queued until the interrupted core borrow unwinds.
                LINK.abandon = true;
            } else if cid == LINK.executing_cid && report[4] == wire::CANCEL && length == 0 {
                LINK.cancelled = true;
                ck_hid_io_consume(LINK.execution_epoch);
            } else if idle {
                if report[4] & 0x80 != 0 {
                    let error = if cid == 0 || (cid == wire::BROADCAST && report[4] != wire::INIT) {
                        Error::Channel as u8
                    } else if cid == LINK.executing_cid && report[4] == wire::INIT {
                        Error::Length as u8
                    } else {
                        Error::Busy as u8
                    };
                    send_control(cid, wire::ERROR, error);
                    idle = false;
                }
                ck_hid_io_consume(LINK.execution_epoch);
            }
            ck_hid_io_receive();
        }
        if LINK.cancelled || LINK.abandon {
            return 0;
        }
        if idle && device_get_tick().wrapping_sub(LINK.keepalive_at) >= 100 {
            send_control(LINK.executing_cid, wire::KEEPALIVE, LINK.keepalive_status);
            LINK.keepalive_at = device_get_tick();
        }
        u8::from(!LINK.abandon)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_execution_end() {
    unsafe {
        while ck_hid_io_reset_pending() == 0 && ck_hid_io_idle() == 0 {
            if device_get_tick().wrapping_sub(LINK.sent_at) >= 1000 {
                LINK.abandon = true;
                break;
            }
            device_delay(1);
        }
        LINK.executing = false;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTAPHID_Loop(_wait_for_user: u8) -> u8 {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        if super::webusb_link::block_competitor() {
            return 0;
        }
        if ck_hid_io_reset_pending() != 0 {
            let generation = ck_hid_io_epoch();
            ck_hid_reset();
            LINK = Link::new();
            // A hardware reset has released the endpoint-owned buffers.
            core::ptr::addr_of_mut!(OUTGOING).write([0; 64]);
            ck_hid_io_ack_reset(generation);
        }
        if ck_hid_io_reset_pending() != 0 || ck_hid_io_configured() == 0 {
            return 0;
        }
        if ck_hid_io_idle() == 0 {
            if LINK.transmitting && device_get_tick().wrapping_sub(LINK.sent_at) >= 1000 {
                ck_hid_reset();
                LINK.active = false;
                LINK.transmitting = false;
                LINK.session_owned = false;
            }
            return 0;
        }
        LINK.transmitting = false;
        let generation = ck_hid_io_epoch();
        let mut report = [0; 64];
        let mut received = 0;
        let has_input = ck_hid_io_peek(
            report.as_mut_ptr(),
            report.len() as u8,
            &mut received,
            generation,
        ) != 0;
        if has_input {
            ck_hid_io_consume(generation);
            ck_hid_io_receive();
        }
        let result = ck_hid_poll(
            if has_input {
                report.as_ptr()
            } else {
                core::ptr::null()
            },
            received,
            device_get_tick(),
            core::ptr::addr_of_mut!(OUTGOING).cast(),
        );
        if generation != ck_hid_io_epoch() {
            return 0;
        }
        if LINK.abandon {
            LINK.abandon = false;
            LINK.active = false;
            LINK.transmitting = false;
            LINK.session_owned = false;
            // Drop the suppressed response before processing the queued INIT.
            ck_hid_reset();
            return 0;
        }
        if LINK.active || result & 2 != 0 {
            LINK.session_owned = true;
            LINK.session_last_used = device_get_tick();
        }
        LINK.active = result & 2 != 0;
        if result & 1 != 0 {
            if ck_hid_io_send(core::ptr::addr_of_mut!(OUTGOING).cast(), generation) == 0 {
                ck_hid_reset();
                LINK = Link::new();
                return 0;
            }
            LINK.sent_at = device_get_tick();
            LINK.transmitting = true;
        }
        ck_hid_io_receive();
        0
    }
}
