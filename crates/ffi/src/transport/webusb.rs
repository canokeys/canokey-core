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
// Shared by EP0 IRQ and the main loop under the USB mask. Core runs with the
// mask released and without a borrow of this structure.
struct WebUsbState {
    transport: Transport,
    waiting: bool,
    // IRQ publishes the packet and the main loop consumes it. Zero is empty.
    packet: [u8; 16],
    packet_length: u8,
    // IRQ may schedule cleanup. Only the main loop performs it.
    cleanup: bool,
    clear_input: bool,
    // The main loop reserves the session and publishes ownership changes.
    session: bool,
    prepare: bool,
}

static mut WEBUSB: WebUsbState = WebUsbState {
    transport: Transport::new(),
    waiting: false,
    packet: [0; 16],
    packet_length: 0,
    cleanup: false,
    clear_input: false,
    session: false,
    prepare: false,
};

/// Competitors yield to an EP0 reservation. A command arriving during a Core
/// call waits in the FIFO mailbox and cannot touch the shared byte buffer.
pub unsafe fn block_competitor() -> bool {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        WEBUSB.cleanup
            || WEBUSB.clear_input
            || WEBUSB.session
            || (&*core::ptr::addr_of!(WEBUSB.transport)).busy()
    })
}
/// Main-loop only: a foreign APDU may replace a completed session. Native HID
/// borrows it instead: its own scratch admission checks retained applet state,
/// and its completion restores the WebUSB card context. Mere polling must not
/// revoke the previous owner's authorization.
pub unsafe fn try_preempt<P: Provider>(requested: bool, preserve_context: bool) -> bool {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe {
        if !requested {
            return false;
        }
        let eligible = usb_locked(|| {
            let eligible = !WEBUSB.cleanup
                && !WEBUSB.clear_input
                && !WEBUSB.waiting
                && WEBUSB.session
                && (&*core::ptr::addr_of!(WEBUSB.transport)).completed_transaction()
                && (preserve_context || can_preempt());
            if eligible && !preserve_context {
                WEBUSB.session = false;
                WEBUSB.prepare = false;
                (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).reset();
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
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe { invalidate(false) }
}
pub unsafe fn lifecycle_reset() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe { invalidate(true) }
}
unsafe fn invalidate(deferred: bool) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        // USB reset can interrupt an unrelated Core operation; only the main
        // loop performs cleanup, never this IRQ-side notification.
        let state = &mut *core::ptr::addr_of_mut!(WEBUSB.transport);
        WEBUSB.cleanup |= deferred || WEBUSB.session || (!WEBUSB.waiting && state.busy());
        WEBUSB.waiting = false;
        WEBUSB.packet_length = 0;
        // Lifecycle cleanup initializes the class on the main loop. Retain its
        // visible status until then, but cancel an interrupted Core operation
        // immediately so it cannot publish its old result.
        if !deferred || state.execution_live().is_some() {
            state.reset();
        }
    }
}
pub unsafe fn abort_control() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if WEBUSB.waiting
            || matches!(
                (&*core::ptr::addr_of!(WEBUSB.transport)).status(),
                canokey_rust_core::runtime::webusb::STATUS_SENDING
                    | canokey_rust_core::runtime::webusb::STATUS_RECEIVING
            )
        {
            // Hardware has quiesced EP0. No Core input was published before
            // complete RX, so abort only the byte transfer, not SELECT/PIN or
            // a previously retained command/response chain.
            WEBUSB.clear_input |= WEBUSB.session && !WEBUSB.waiting;
            if WEBUSB.prepare {
                WEBUSB.session = false;
                WEBUSB.prepare = false;
            }
            WEBUSB.waiting = false;
            WEBUSB.packet_length = 0;
            (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).reset();
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
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        let now = device_get_tick();
        (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).keepalive(now);
        let request = Request::decode(s, interface)?;
        let state = &mut *core::ptr::addr_of_mut!(WEBUSB.transport);
        Some(match request {
            Request::Command(length) => {
                // Global configuration can precede serialized session cleanup.
                // EP0 status/enumeration remains available during that interval.
                let admitted = usb_ready && !WEBUSB.cleanup;
                if state.command(length, now, admitted) {
                    WEBUSB.waiting = true;
                    WEBUSB.packet_length = 0;
                    Action::Receive
                } else {
                    Action::Reject
                }
            }
            Request::Response(length) if usb_ready && !WEBUSB.cleanup => {
                match state.response(length, now) {
                    Some(n) => Action::Send(n),
                    None => Action::Reject,
                }
            }
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
    // SAFETY: The masked IRQ owns the live packet; the size check bounds the mailbox copy.
    unsafe {
        if length == 0 || length > 16 || WEBUSB.packet_length != 0 {
            return -1;
        }
        core::ptr::copy_nonoverlapping(
            bytes,
            core::ptr::addr_of_mut!(WEBUSB.packet).cast(),
            length,
        );
        WEBUSB.packet_length = length.to_le_bytes()[0];
        // Backpressure every packet until the main loop has consumed it.
        2
    }
}
pub unsafe fn pointer(offset: usize) -> *const u8 {
    // SAFETY: The masked caller holds the WebUSB response lease and a cursor inside its buffer.
    unsafe { crate::transport::ccid::ck_ccid_response_buffer().add(offset) }
}
pub unsafe fn completed() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).completed(device_get_tick());
    }
}
/// Consume an IRQ-published lifecycle event without admitting another command.
pub(crate) unsafe fn service_reset<P: Provider>() {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe {
        let cleanup = usb_locked(|| {
            let cleanup = WEBUSB.cleanup;
            if cleanup {
                WEBUSB.cleanup = false;
                WEBUSB.session = false;
                WEBUSB.prepare = false;
                (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).reset();
            }
            cleanup
        });
        if cleanup {
            ck_core_reset::<P>();
        }
        let clear = usb_locked(|| {
            let clear = WEBUSB.clear_input;
            WEBUSB.clear_input = false;
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
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn poll<P: Provider>() {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return;
        }
        service_reset::<P>();
        usb_locked(|| (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).expire(device_get_tick()));
        usb_locked(|| {
            if !WEBUSB.waiting || WEBUSB.cleanup {
                return;
            }
            let admitted = WEBUSB.session || ck_ccid_idle() != 0;
            #[cfg(feature = "usb-hid")]
            let admitted = admitted && ck_hid_busy() == 0;
            WEBUSB.waiting = false;
            if admitted {
                WEBUSB.prepare |= !WEBUSB.session;
                WEBUSB.session = true;
            } else {
                WEBUSB.packet_length = 0;
                (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).reset();
                crate::transport::usb::web_admission(false, false);
            }
        });
        let mut bytes = [0; 16];
        let packet = usb_locked(|| {
            if WEBUSB.waiting || WEBUSB.cleanup || !WEBUSB.session {
                return None;
            }
            let n = usize::from(WEBUSB.packet_length);
            if n == 0 {
                return None;
            }
            WEBUSB.packet_length = 0;
            bytes[..n].copy_from_slice(&(&*core::ptr::addr_of!(WEBUSB.packet))[..n]);
            let offset =
                (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).receive(n, device_get_tick());
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
                    (&*core::ptr::addr_of!(WEBUSB.transport)).status() == 1,
                )
            });
        }
        let command = usb_locked(|| {
            if WEBUSB.cleanup || WEBUSB.clear_input || WEBUSB.waiting {
                None
            } else {
                (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).execute()
            }
        });
        if let Some(length) = command {
            let prepare = usb_locked(|| {
                let prepare = WEBUSB.prepare;
                WEBUSB.prepare = false;
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
                if (&mut *core::ptr::addr_of_mut!(WEBUSB.transport)).finish(n, device_get_tick()) {
                    WEBUSB.session = true;
                } else {
                    WEBUSB.cleanup = true;
                }
            });
        }
    }
}

pub unsafe fn progress() -> Option<bool> {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        (&*core::ptr::addr_of!(WEBUSB.transport))
            .execution_live()
            .map(|live| live && !WEBUSB.cleanup)
    })
}

#[cfg(test)]
unsafe fn ck_core_reset<P: Provider>() {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe { crate::transport::usb::tests::ck_core_reset() }
}
#[cfg(not(test))]
unsafe fn begin_frame<P: Provider>(
    length: usize,
) -> Result<(), canokey_protocol::response::StatusWord> {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
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
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe { crate::composition::core::with_core::<P, _>(|core, p| core.feed_frame(bytes, p)) }
}
#[cfg(not(test))]
unsafe fn finish_frame<P: Provider>(
    error: Option<canokey_protocol::response::StatusWord>,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe {
        crate::composition::core::with_core::<P, _>(|core, p| {
            let reply = if let Some(sw) = error {
                core.abort_request(OWNER_WEBUSB, p);
                canokey_rust_core::runtime::engine::Reply::Status(sw)
            } else {
                core.end_frame(p)
            };
            core.transmit(reply, core::slice::from_raw_parts_mut(out, capacity), p)
                .map_or(-1, |n| i32::try_from(n).unwrap())
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
    // SAFETY: The serialized main loop owns the WebUSB session; each mailbox access keeps its USB mask.
    unsafe { crate::transport::usb::tests::web_finish(OWNER_WEBUSB, out, capacity) }
}
