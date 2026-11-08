// SPDX-License-Identifier: Apache-2.0
//! EP0/main-loop handoff. All state access is IRQ-masked; Core runs unmasked
//! with no live borrow of STATE. The existing CCID response allocation is also
//! the WebUSB RX/TX allocation, exclusively leased by main-loop admission.
//! Core sees a command only after complete RX, preserving an earlier response
//! source or command chain when a new SETUP aborts a partial control transfer.
//! A single 16-byte FIFO mailbox holds a data-stage OUT packet received after
//! SETUP admission but before the main loop accepts the command.
use crate::composition::Provider;
#[cfg(not(test))]
use crate::composition::core::{can_preempt, reset as ck_core_reset};
use crate::sys::device_get_tick;
#[cfg(not(test))]
use crate::transport::ccid::ck_ccid_idle;
#[cfg(all(not(test), feature = "usb-hid"))]
use crate::transport::hid::link::ck_hid_busy;
use crate::transport::owners::OWNER_WEBUSB;
#[cfg(all(test, feature = "usb-hid"))]
use crate::transport::usb::tests::ck_hid_busy;
#[cfg(test)]
use crate::transport::usb::tests::{can_preempt, ck_ccid_idle};
use crate::transport::usb_locked;
use canokey_protocol::usb::Setup;
use canokey_rust_core::runtime::webusb::{RESPONSE_LIMIT, Request, Transport};
static mut STATE: Transport = Transport::new();
static mut WAITING: bool = false;
static mut PACKET: [u8; 16] = [0; 16];
static mut PACKET_LENGTH: Option<usize> = None;
static mut CLEANUP: bool = false;
static mut SESSION: bool = false;
// A reservation may still refer to a foreign applet context. Switch it only
// when the complete command enters Core; aborted RX must leave it intact.
static mut PREPARE: bool = false;
static mut CLEAR_INPUT: bool = false;

/// Competitors yield to an EP0 reservation. A command arriving during a Core
/// call waits in the FIFO mailbox and cannot touch the shared byte buffer.
pub unsafe fn block_competitor() -> bool {
    usb_locked(|| unsafe {
        CLEANUP || CLEAR_INPUT || SESSION || (&*core::ptr::addr_of!(STATE)).busy()
    })
}
/// Main-loop only: a foreign APDU may replace a completed session. Native HID
/// borrows it instead: its own scratch admission checks retained applet state,
/// and its completion restores the WebUSB card context. Mere polling must not
/// revoke the previous owner's authorization.
pub unsafe fn try_preempt<P: Provider>(requested: bool, preserve_context: bool) -> bool {
    unsafe {
        if !requested {
            return false;
        }
        let eligible = usb_locked(|| {
            let eligible = !CLEANUP
                && !CLEAR_INPUT
                && !WAITING
                && SESSION
                && (&*core::ptr::addr_of!(STATE)).completed_transaction()
                && (preserve_context || can_preempt());
            if eligible && !preserve_context {
                SESSION = false;
                PREPARE = false;
                (&mut *core::ptr::addr_of_mut!(STATE)).reset();
            }
            eligible
        });
        if eligible && !preserve_context {
            ck_core_reset::<P>();
        }
        eligible
    }
}
pub unsafe fn reset() {
    unsafe { invalidate(false) }
}
pub unsafe fn lifecycle_reset() {
    unsafe { invalidate(true) }
}
unsafe fn invalidate(deferred: bool) {
    unsafe {
        // USB reset can interrupt an unrelated Core operation; only the main
        // loop performs cleanup, never this IRQ-side notification.
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        CLEANUP |= deferred || SESSION || (!WAITING && state.busy());
        WAITING = false;
        PACKET_LENGTH = None;
        // Lifecycle cleanup initializes the class on the main loop. Retain its
        // visible status until then, but cancel an interrupted Core operation
        // immediately so it cannot publish its old result.
        if !deferred || state.execution_live().is_some() {
            state.reset();
        }
    }
}
pub unsafe fn abort_control() {
    unsafe {
        if WAITING
            || matches!(
                (&*core::ptr::addr_of!(STATE)).status(),
                canokey_rust_core::runtime::webusb::STATUS_SENDING
                    | canokey_rust_core::runtime::webusb::STATUS_RECEIVING
            )
        {
            // Hardware has quiesced EP0. No Core input was published before
            // complete RX, so abort only the byte transfer, not SELECT/PIN or
            // a previously retained command/response chain.
            CLEAR_INPUT |= SESSION && !WAITING;
            if PREPARE {
                SESSION = false;
                PREPARE = false;
            }
            WAITING = false;
            PACKET_LENGTH = None;
            (&mut *core::ptr::addr_of_mut!(STATE)).reset();
        }
    }
}
pub enum Action {
    Receive,
    Send(usize),
    Status(u8),
    Reject,
}
pub unsafe fn setup(s: Setup, interface: u8, usb_ready: bool) -> Option<Action> {
    unsafe {
        let now = device_get_tick();
        (&mut *core::ptr::addr_of_mut!(STATE)).keepalive(now);
        let request = Request::decode(s, interface)?;
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        Some(match request {
            Request::Command(length) => {
                // Global configuration can precede serialized session cleanup.
                // EP0 status/enumeration remains available during that interval.
                let admitted = usb_ready && !CLEANUP;
                if state.command(length, now, admitted) {
                    WAITING = true;
                    PACKET_LENGTH = None;
                    Action::Receive
                } else {
                    Action::Reject
                }
            }
            Request::Response(length) if usb_ready && !CLEANUP => match state.response(length, now)
            {
                Some(n) => Action::Send(n),
                None => Action::Reject,
            },
            Request::Response(_) => Action::Reject,
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
        if length == 0 || length > 16 || matches!(PACKET_LENGTH, Some(_)) {
            return -1;
        }
        core::ptr::copy_nonoverlapping(bytes, core::ptr::addr_of_mut!(PACKET).cast(), length);
        PACKET_LENGTH = Some(length);
        // Backpressure every packet until the main loop has consumed it.
        2
    }
}
pub unsafe fn pointer(offset: usize) -> *const u8 {
    unsafe { crate::transport::ccid::ck_ccid_response_buffer().add(offset) }
}
pub unsafe fn completed() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(STATE)).completed(device_get_tick());
    }
}
/// Consume an IRQ-published lifecycle event without admitting another command.
pub(crate) unsafe fn service_reset<P: Provider>() {
    unsafe {
        let cleanup = usb_locked(|| {
            let cleanup = CLEANUP;
            if cleanup {
                CLEANUP = false;
                SESSION = false;
                PREPARE = false;
                (&mut *core::ptr::addr_of_mut!(STATE)).reset();
            }
            cleanup
        });
        if cleanup {
            ck_core_reset::<P>();
        }
        let clear = usb_locked(|| {
            let clear = CLEAR_INPUT;
            CLEAR_INPUT = false;
            clear
        });
        if clear {
            core::ptr::write_bytes(
                crate::transport::ccid::ck_ccid_response_buffer(),
                0,
                crate::transport::ccid::SHARED_IO_BYTES,
            );
        }
    }
}
#[inline(never)]
pub unsafe fn poll<P: Provider>() {
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return;
        }
        service_reset::<P>();
        usb_locked(|| (&mut *core::ptr::addr_of_mut!(STATE)).expire(device_get_tick()));
        usb_locked(|| {
            if !WAITING || CLEANUP {
                return;
            }
            let admitted = SESSION || ck_ccid_idle() != 0;
            #[cfg(feature = "usb-hid")]
            let admitted = admitted && ck_hid_busy() == 0;
            WAITING = false;
            if admitted {
                PREPARE |= !SESSION;
                SESSION = true;
            } else {
                PACKET_LENGTH = None;
                (&mut *core::ptr::addr_of_mut!(STATE)).reset();
                crate::transport::usb::web_admission(false, false);
            }
        });
        let mut bytes = [0; 16];
        let packet = usb_locked(|| {
            if WAITING || CLEANUP || !SESSION {
                return None;
            }
            let n = PACKET_LENGTH?;
            PACKET_LENGTH = None;
            bytes[..n].copy_from_slice(&(&*core::ptr::addr_of!(PACKET))[..n]);
            let offset = (&mut *core::ptr::addr_of_mut!(STATE)).receive(n, device_get_tick());
            Some((n, offset))
        });
        if let Some((n, offset)) = packet {
            if let Some(offset) = offset {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    crate::transport::ccid::ck_ccid_response_buffer().add(offset),
                    n,
                );
            } else {
                abort_control();
            }
            bytes.fill(0);
            let valid = offset.is_some();
            usb_locked(|| {
                crate::transport::usb::web_admission(
                    valid,
                    (&*core::ptr::addr_of!(STATE)).status() == 1,
                )
            });
        }
        let command = usb_locked(|| {
            if CLEANUP || CLEAR_INPUT || WAITING {
                None
            } else {
                (&mut *core::ptr::addr_of_mut!(STATE)).execute()
            }
        });
        if let Some(length) = command {
            let prepare = usb_locked(|| {
                let prepare = PREPARE;
                PREPARE = false;
                prepare
            });
            if prepare {
                ck_core_reset::<P>();
            }
            let buffer = crate::transport::ccid::ck_ccid_response_buffer();
            let input = core::slice::from_raw_parts(buffer, length);
            let n = if canokey_protocol::apdu::parse(input).is_err() {
                // C validates the complete WebUSB envelope before routing.
                // Malformed input must not cancel an earlier FIDO chain.
                core::ptr::copy_nonoverlapping(
                    canokey_protocol::response::StatusWord::WRONG_LENGTH
                        .bytes()
                        .as_ptr(),
                    buffer,
                    2,
                );
                2
            } else {
                let error = begin_frame::<P>(length)
                    .and_then(|()| feed_frame::<P>(input))
                    .err();
                finish_frame::<P>(error, buffer, RESPONSE_LIMIT)
            };
            let n = if n < 0 {
                // Preserve a pollable APDU failure on a response-source error.
                *buffer = 0x6f;
                *buffer.add(1) = 0;
                2
            } else {
                n as usize
            };
            usb_locked(|| {
                if (&mut *core::ptr::addr_of_mut!(STATE)).finish(n, device_get_tick()) {
                    SESSION = true;
                } else {
                    CLEANUP = true;
                }
            });
        }
    }
}

pub unsafe fn progress() -> Option<bool> {
    usb_locked(|| unsafe {
        (&*core::ptr::addr_of!(STATE))
            .execution_live()
            .map(|live| live && !CLEANUP)
    })
}

#[cfg(test)]
unsafe fn ck_core_reset<P: Provider>() {
    unsafe { crate::transport::usb::tests::ck_core_reset() }
}
#[cfg(not(test))]
unsafe fn begin_frame<P: Provider>(
    length: usize,
) -> Result<(), canokey_protocol::response::StatusWord> {
    unsafe {
        crate::composition::core::with_core::<P, _>(|core, p| {
            core.begin_frame(OWNER_WEBUSB, length, p)
        })
    }
}
#[cfg(not(test))]
unsafe fn feed_frame<P: Provider>(
    bytes: &[u8],
) -> Result<(), canokey_protocol::response::StatusWord> {
    unsafe { crate::composition::core::with_core::<P, _>(|core, p| core.feed_frame(bytes, p)) }
}
#[cfg(not(test))]
unsafe fn finish_frame<P: Provider>(
    error: Option<canokey_protocol::response::StatusWord>,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    unsafe {
        crate::composition::core::with_core::<P, _>(|core, p| {
            let reply = if let Some(sw) = error {
                core.abort_request(OWNER_WEBUSB, p);
                canokey_rust_core::runtime::engine::Reply::Status(sw)
            } else {
                core.end_frame(p)
            };
            core.transmit(reply, core::slice::from_raw_parts_mut(out, capacity), p)
                .map_or(-1, |n| n as i32)
        })
    }
}
#[cfg(test)]
unsafe fn begin_frame<P: Provider>(
    length: usize,
) -> Result<(), canokey_protocol::response::StatusWord> {
    crate::transport::usb::tests::web_begin(length);
    Ok(())
}
#[cfg(test)]
unsafe fn feed_frame<P: Provider>(
    bytes: &[u8],
) -> Result<(), canokey_protocol::response::StatusWord> {
    crate::transport::usb::tests::web_feed(bytes);
    Ok(())
}
#[cfg(test)]
unsafe fn finish_frame<P: Provider>(
    error: Option<canokey_protocol::response::StatusWord>,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    assert!(error.is_none());
    unsafe { crate::transport::usb::tests::web_finish(OWNER_WEBUSB, out, capacity) }
}
