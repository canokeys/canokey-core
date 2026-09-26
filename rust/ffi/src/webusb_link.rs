// SPDX-License-Identifier: Apache-2.0
//! EP0/main-loop handoff. All state access is IRQ-masked; Core runs unmasked
//! with no live borrow of STATE. The existing CCID response allocation is also
//! the WebUSB RX/TX allocation, exclusively leased by main-loop admission.
//! A single 16-byte FIFO mailbox bridges SETUP arriving during another call.
use canokey_protocol::usb::Setup;
use canokey_rust_core::runtime::webusb::{RESPONSE_LIMIT, Request, Transport};
unsafe extern "C" {
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
    fn device_get_tick() -> u32;
    fn ck_ccid_idle() -> u8;
    fn ck_ccid_response_buffer() -> *mut u8;
    fn ck_core_reset();
    fn ck_core_exchange(
        owner: u8,
        input: *const u8,
        len: usize,
        output: *mut u8,
        capacity: usize,
    ) -> i32;
    #[cfg(feature = "usb-hid")]
    fn ck_hid_busy() -> u8;
}
static mut STATE: Transport = Transport::new();
static mut WAITING: bool = false;
static mut PACKET: [u8; 16] = [0; 16];
static mut PACKET_LENGTH: Option<usize> = None;
static mut CLEANUP: bool = false;
static mut SESSION: bool = false;

/// Competitors yield to an EP0 reservation. A command arriving during a Core
/// call waits in the FIFO mailbox and cannot touch the shared byte buffer.
pub unsafe fn block_competitor() -> bool {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let blocked = CLEANUP || (&*core::ptr::addr_of!(STATE)).busy();
        ck_usb_dcd_unlock(mask);
        blocked
    }
}
pub unsafe fn reset() {
    unsafe {
        // USB reset can interrupt an unrelated Core operation; only the main
        // loop performs cleanup, never this IRQ-side notification.
        CLEANUP |= SESSION || (!WAITING && (&*core::ptr::addr_of!(STATE)).busy());
        WAITING = false;
        PACKET_LENGTH = None;
        (&mut *core::ptr::addr_of_mut!(STATE)).reset();
    }
}
pub unsafe fn abort_control() {
    unsafe {
        if WAITING || matches!((&*core::ptr::addr_of!(STATE)).status(), 2 | 3) {
            reset();
        }
    }
}
pub enum Action {
    Receive,
    Send(usize),
    Status(u8),
    Reject,
}
pub unsafe fn setup(s: Setup, interface: u8) -> Option<Action> {
    let request = Request::decode(s, interface)?;
    unsafe {
        let now = device_get_tick();
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        Some(match request {
            Request::Command(length) => {
                let admitted = !CLEANUP;
                if state.command(length, now, admitted) {
                    WAITING = true;
                    PACKET_LENGTH = None;
                    Action::Receive
                } else {
                    Action::Reject
                }
            }
            Request::Response(length) => match state.response(length, now) {
                Some(n) => Action::Send(n),
                None => Action::Reject,
            },
            Request::Status => {
                state.keepalive(now);
                Action::Status(state.status())
            }
        })
    }
}
// 0: more data, 1: complete, 2: held FIFO awaiting main-loop admission.
pub unsafe fn receive(bytes: *const u8, length: usize) -> i8 {
    unsafe {
        if WAITING {
            if length == 0 || length > 16 || matches!(PACKET_LENGTH, Some(_)) {
                return -1;
            }
            core::ptr::copy_nonoverlapping(bytes, core::ptr::addr_of_mut!(PACKET).cast(), length);
            PACKET_LENGTH = Some(length);
            return 2;
        }
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        let Some(offset) = state.receive(length, device_get_tick()) else {
            return -1;
        };
        core::ptr::copy_nonoverlapping(bytes, ck_ccid_response_buffer().add(offset), length);
        i8::from(state.status() == 1)
    }
}
pub unsafe fn pointer(offset: usize) -> *const u8 {
    unsafe { ck_ccid_response_buffer().add(offset) }
}
pub unsafe fn completed() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(STATE)).completed(device_get_tick());
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WebUSB_Loop() {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let cleanup = CLEANUP || (&*core::ptr::addr_of!(STATE)).expired(device_get_tick());
        if cleanup {
            CLEANUP = false;
            SESSION = false;
            (&mut *core::ptr::addr_of_mut!(STATE)).reset();
        }
        ck_usb_dcd_unlock(mask);
        if cleanup {
            ck_core_reset();
        }

        let mask = ck_usb_dcd_lock();
        if WAITING && !CLEANUP {
            let idle = ck_ccid_idle() != 0;
            #[cfg(feature = "usb-hid")]
            let idle = idle && ck_hid_busy() == 0;
            WAITING = false;
            if SESSION || idle {
                let mut valid = true;
                if let Some(n) = PACKET_LENGTH {
                    valid = receive(core::ptr::addr_of!(PACKET).cast(), n) >= 0;
                }
                PACKET_LENGTH = None;
                super::usb::web_admission(valid, (&*core::ptr::addr_of!(STATE)).status() == 1);
                if !valid {
                    reset();
                }
            } else {
                // Refused admission must never reset a foreign applet session.
                PACKET_LENGTH = None;
                (&mut *core::ptr::addr_of_mut!(STATE)).reset();
                super::usb::web_admission(false, false);
            }
        }
        let command = if CLEANUP {
            None
        } else {
            (&mut *core::ptr::addr_of_mut!(STATE)).execute()
        };
        let new_session = !SESSION;
        ck_usb_dcd_unlock(mask);
        if let Some(length) = command {
            if new_session {
                ck_core_reset();
            }
            let buffer = ck_ccid_response_buffer();
            // ck_core_exchange ends the input borrow before creating output.
            let n = ck_core_exchange(3, buffer, length, buffer, RESPONSE_LIMIT);
            let n = if n < 0 {
                // Preserve a pollable APDU failure on a response-source error.
                *buffer = 0x6f;
                *buffer.add(1) = 0;
                2
            } else {
                n as usize
            };
            let mask = ck_usb_dcd_lock();
            if (&mut *core::ptr::addr_of_mut!(STATE)).finish(n, device_get_tick()) {
                SESSION = true;
            } else {
                CLEANUP = true;
            }
            ck_usb_dcd_unlock(mask);
        }
    }
}

pub unsafe fn progress() -> Option<bool> {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let live = (&*core::ptr::addr_of!(STATE))
            .execution_live()
            .map(|live| live && !CLEANUP);
        ck_usb_dcd_unlock(mask);
        live
    }
}
