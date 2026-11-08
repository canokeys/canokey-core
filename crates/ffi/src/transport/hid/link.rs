// SPDX-License-Identifier: Apache-2.0
//! Serialized HID link policy. IRQs access only the native mailbox, never this
//! state. Core execution may call progress, so no state borrow crosses a poll.
use crate::composition::Provider;
use canokey_protocol::ctaphid::{self as wire, Error};
use canokey_transport_runtime::ctaphid::{Execution as SharedExecution, ExecutionPolicy, Incoming};
struct CanoKey;
impl ExecutionPolicy for CanoKey {
    const MALFORMED_INIT_ERROR: Error = Error::Length;
}
type Execution = SharedExecution<CanoKey>;

const TX_TIMEOUT_MS: u32 = 1000;
#[cfg(not(all(test, not(feature = "usb-device"))))]
use super::command::{poll as ck_hid_poll, reset as ck_hid_reset};
#[cfg(all(test, not(feature = "usb-device")))]
pub(crate) mod tests;
use super::io::{
    ck_hid_io_ack_reset, ck_hid_io_configured, ck_hid_io_consume, ck_hid_io_epoch, ck_hid_io_idle,
    ck_hid_io_peek, ck_hid_io_receive, ck_hid_io_reset_pending, ck_hid_io_send,
};
#[cfg(not(all(test, not(feature = "usb-device"))))]
use crate::sys::{device_delay, device_get_tick};
#[cfg(all(test, not(feature = "usb-device")))]
use tests::{ck_hid_poll, ck_hid_reset, device_delay, device_get_tick};
// Separate endpoint-owned buffers: progress runs while poll borrows OUTGOING.
static mut OUTGOING: [u8; 64] = [0; 64];
static mut CONTROL: [u8; 64] = [0; 64];
struct Link {
    sent_at: u32,
    active: bool,
    retained: bool,
    transmitting: bool,
    execution: Execution,
    keepalive_status: u8,
}
impl Link {
    const fn new() -> Self {
        Self {
            sent_at: 0,
            active: false,
            retained: false,
            transmitting: false,
            execution: Execution::inactive(),
            // Execution begin supplies the wire status before any keepalive.
            keepalive_status: 0,
        }
    }
}
static mut LINK: Link = Link::new();
// Serialized main-loop/progress state, never borrowed across mailbox or IO calls.
unsafe fn execution() -> &'static mut Execution {
    unsafe { &mut *core::ptr::addr_of_mut!(LINK.execution) }
}
unsafe fn peek_header(epoch: u32) -> Option<(u32, u8, u16)> {
    let mut header = [0; 7];
    let mut received = 0;
    if unsafe {
        ck_hid_io_peek(
            header.as_mut_ptr(),
            header.len() as u8,
            &mut received,
            epoch,
        )
    } == 0
    {
        return None;
    }
    Some((
        u32::from_be_bytes(header[..4].try_into().unwrap()),
        header[4],
        u16::from_be_bytes([header[5], header[6]]),
    ))
}
pub unsafe extern "C" fn ck_hid_active() -> u8 {
    unsafe { u8::from(LINK.active) }
}
#[inline(never)]
pub unsafe extern "C" fn ck_hid_busy() -> u8 {
    unsafe { u8::from(LINK.active || LINK.retained || LINK.transmitting) }
}
pub unsafe fn ck_hid_executing() -> u8 {
    unsafe { u8::from(execution().executing()) }
}
/// Command admission supplies a nonzero CID; reserved CID zero marks inactivity.
pub unsafe fn ck_hid_execution_begin(cid: u32) {
    unsafe {
        LINK.execution = Execution::new(cid, ck_hid_io_epoch(), device_get_tick());
        LINK.active = true;
        LINK.keepalive_status = wire::STATUS_PROCESSING;
    }
}
pub unsafe fn ck_hid_keepalive(waiting: u8) {
    unsafe {
        LINK.keepalive_status = if waiting != 0 {
            wire::STATUS_UPNEEDED
        } else {
            wire::STATUS_PROCESSING
        };
    }
}
unsafe fn send_control(cid: u32, command: u8, value: u8, epoch: u32) {
    unsafe {
        let report = &mut *core::ptr::addr_of_mut!(CONTROL);
        wire::header(report, cid, command, 1)[0] = value;
        if ck_hid_io_send(report.as_ptr(), epoch) == 0 {
            execution().abandon();
            return;
        }
        LINK.sent_at = device_get_tick();
        LINK.transmitting = true;
    }
}
/// Service competing HID traffic while another transport borrows Core.
/// No transport poll/reset or session cleanup is allowed on this call path.
#[cfg(any(feature = "usb-device", test))]
#[cfg_attr(all(test, feature = "usb-device"), allow(dead_code))]
pub unsafe fn ck_hid_foreign_progress() {
    unsafe {
        if execution().executing()
            || ck_hid_io_reset_pending() != 0
            || ck_hid_io_configured() == 0
            || ck_hid_io_idle() == 0
        {
            return;
        }
        let epoch = ck_hid_io_epoch();
        let Some((cid, command, _)) = peek_header(epoch) else {
            return;
        };
        // CANCEL belongs to its HID operation, never to the unrelated APDU.
        // Continuations cannot start a new command and are silently drained.
        if command & wire::CMD_INIT_BIT != 0 && command != wire::CANCEL {
            let error =
                canokey_transport_runtime::ctaphid::classify_error::<CanoKey>(cid, command, None);
            send_control(cid, wire::ERROR, error as u8, epoch);
        }
        ck_hid_io_consume(epoch);
        ck_hid_io_receive();
    }
}
pub unsafe fn ck_hid_progress() -> u8 {
    unsafe {
        if !execution().executing() || ck_hid_io_reset_pending() != 0 || ck_hid_io_configured() == 0
        {
            return 0;
        }
        let mut idle = ck_hid_io_idle() != 0;
        if !idle
            && LINK.transmitting
            && device_get_tick().wrapping_sub(LINK.sent_at) >= TX_TIMEOUT_MS
        {
            execution().abandon();
        }
        // Only the initial header is needed while crypto owns the core stack.
        if let Some((cid, command, length)) = peek_header(execution().epoch()) {
            let length = (command & wire::CMD_INIT_BIT != 0).then_some(usize::from(length));
            let incoming = execution().receive_header(cid, command, length);
            match incoming {
                Incoming::Retain => {}
                Incoming::Consume => {
                    // CANCEL is consumed even while a keepalive owns IN;
                    // other continuations retain their mailbox until IN is idle.
                    if idle
                        || (cid == execution().cid()
                            && command == wire::CANCEL
                            && length == Some(0))
                    {
                        ck_hid_io_consume(execution().epoch());
                    }
                }
                Incoming::Error(error) => {
                    if idle {
                        send_control(cid, wire::ERROR, error as u8, execution().epoch());
                        idle = false;
                        ck_hid_io_consume(execution().epoch());
                    }
                }
            }
            ck_hid_io_receive();
        }
        if execution().cancelled() || execution().abandoned() {
            return 0;
        }
        if idle && execution().keepalive_due(device_get_tick()) {
            send_control(
                execution().cid(),
                wire::KEEPALIVE,
                LINK.keepalive_status,
                execution().epoch(),
            );
            execution().keepalive_sent(device_get_tick());
        }
        u8::from(!execution().abandoned())
    }
}
pub unsafe fn ck_hid_execution_end() {
    unsafe {
        while ck_hid_io_reset_pending() == 0 && ck_hid_io_idle() == 0 {
            if device_get_tick().wrapping_sub(LINK.sent_at) >= TX_TIMEOUT_MS {
                execution().abandon();
                break;
            }
            device_delay(1);
        }
        execution().end();
    }
}
/// Main-loop cleanup only; never dispatch a queued report during enumeration.
pub(crate) unsafe fn service_reset<P: Provider>() {
    unsafe {
        if ck_hid_io_reset_pending() != 0 {
            let generation = ck_hid_io_epoch();
            ck_hid_reset::<P>();
            LINK = Link::new();
            // A hardware reset has released the endpoint-owned buffers.
            core::ptr::addr_of_mut!(OUTGOING).write([0; 64]);
            ck_hid_io_ack_reset(generation);
        }
    }
}
#[inline(never)]
pub unsafe fn poll<P: Provider>() -> u8 {
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return 0;
        }
        service_reset::<P>();
        #[cfg(feature = "usb-webusb")]
        if !LINK.active && crate::transport::webusb::block_competitor() {
            let header = (ck_hid_io_reset_pending() == 0
                && ck_hid_io_configured() != 0
                && ck_hid_io_idle() != 0)
                .then(|| peek_header(ck_hid_io_epoch()))
                .flatten();
            let requested = header.is_some_and(|(cid, command, _)| {
                !matches!(cid, 0 | wire::BROADCAST)
                    && matches!(command, wire::PING | wire::MSG | wire::CBOR | wire::WINK)
            });
            // Idle INIT/CANCEL touch only HID state. Process them without
            // revoking the foreign context or leaving the mailbox blocked.
            let control = header.is_some_and(|(_, command, length)| {
                matches!(command, wire::INIT | wire::CANCEL)
                    || canokey_rust_core::runtime::ctaphid::preserves_context(
                        command,
                        usize::from(length),
                    )
            });
            if header.is_some()
                && !control
                && !crate::transport::webusb::try_preempt::<P>(requested, true)
            {
                return 0;
            }
        }
        if ck_hid_io_reset_pending() != 0 || ck_hid_io_configured() == 0 {
            return 0;
        }
        if ck_hid_io_idle() == 0 {
            if LINK.transmitting && device_get_tick().wrapping_sub(LINK.sent_at) >= TX_TIMEOUT_MS {
                ck_hid_reset::<P>();
                LINK.active = false;
                LINK.retained = false;
                LINK.transmitting = false;
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
        let result = ck_hid_poll::<P>(
            if has_input {
                core::ptr::addr_of!(report)
            } else {
                core::ptr::null()
            },
            received,
            device_get_tick(),
            core::ptr::addr_of_mut!(OUTGOING),
        );
        if generation != ck_hid_io_epoch() {
            return 0;
        }
        if execution().abandoned() {
            execution().clear_abandonment();
            LINK.active = false;
            LINK.retained = false;
            LINK.transmitting = false;
            // Drop the suppressed response before processing the queued INIT.
            ck_hid_reset::<P>();
            return 0;
        }
        LINK.active = result & 2 != 0;
        LINK.retained = result & 4 != 0;
        if result & 1 != 0 {
            if ck_hid_io_send(core::ptr::addr_of_mut!(OUTGOING).cast(), generation) == 0 {
                ck_hid_reset::<P>();
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
