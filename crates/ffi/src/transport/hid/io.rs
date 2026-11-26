// SPDX-License-Identifier: Apache-2.0
//! USB IRQ report mailbox and reset epochs, disjoint from CTAPHID execution.
#[cfg(all(test, not(feature = "usb-device")))]
use super::link::tests::ck_platform_now;
#[cfg(not(all(test, not(feature = "usb-device"))))]
use crate::sys::ck_platform_now;
use crate::transport::usb_io::{ck_usb_configured, ck_usb_receive, ck_usb_submit, ck_usb_tx_idle};
use crate::transport::usb_locked;
use canokey_protocol::usb::*;
static mut INCOMING: [u8; 64] = [0; 64];
static mut QUEUED: bool = false;
static mut RESET: bool = false;
static mut EPOCH: u32 = 0;
static mut RECEIVED: u32 = 0;
///
/// # Safety
/// Only the serialized USB IRQ producer may act on the receive mailbox snapshot.
pub unsafe fn rx_can_accept() -> u8 {
    // SAFETY: This reads the controller's IRQ-published scalar without borrowing the mailbox.
    unsafe { u8::from(!core::ptr::read_volatile(core::ptr::addr_of!(QUEUED))) }
}
///
/// # Safety
/// `data` must be readable for a full HID report. Call from the serialized USB IRQ producer.
pub unsafe fn out_event(data: *const u8) -> u8 {
    // SAFETY: The USB mask protects the RX mailbox; the controller supplies the live packet bytes.
    usb_locked(|| unsafe {
        if QUEUED || data.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(data, core::ptr::addr_of_mut!(INCOMING).cast(), 64);
        RECEIVED = ck_platform_now();
        QUEUED = true;
        1
    })
}
///
/// # Safety
/// Serialize endpoint reset with the USB IRQ producer, after discarding any stale hardware transfer.
pub unsafe fn ck_hid_packet_reset() {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        EPOCH = EPOCH.wrapping_add(1);
        RESET = true;
        QUEUED = false;
    });
}
#[cfg(feature = "usb-device")]
pub unsafe fn ck_hid_packet_out(data: *const u8) -> u8 {
    // SAFETY: The caller serializes access to the controller mailbox and keeps any transfer buffer live.
    unsafe {
        out_event(data);
    }
    0 // Only main-loop consumption releases the FIFO.
}
pub unsafe fn ck_hid_io_epoch() -> u32 {
    // SAFETY: This reads the controller's IRQ-published scalar without borrowing the mailbox.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EPOCH)) }
}
pub unsafe fn ck_hid_io_reset_pending() -> u8 {
    // SAFETY: This reads the controller's IRQ-published scalar without borrowing the mailbox.
    unsafe { u8::from(core::ptr::read_volatile(core::ptr::addr_of!(RESET))) }
}
pub unsafe fn ck_hid_io_ack_reset(generation: u32) {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        if EPOCH == generation {
            RESET = false;
        }
    });
}
pub unsafe fn ck_hid_io_configured() -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe { ck_usb_configured() })
}
pub unsafe fn ck_hid_io_idle() -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe { ck_usb_tx_idle(EP_HID_IN) })
}
pub unsafe fn ck_hid_io_peek(report: *mut u8, length: u8, tick: *mut u32, generation: u32) -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        let ok =
            generation == EPOCH && QUEUED && length <= 64 && !report.is_null() && !tick.is_null();
        if ok {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(INCOMING).cast(),
                report,
                usize::from(length),
            );
            tick.write(RECEIVED);
        }
        u8::from(ok)
    })
}
pub unsafe fn ck_hid_io_consume(generation: u32) {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        if generation == EPOCH {
            QUEUED = false;
        }
    });
}
pub unsafe fn ck_hid_io_receive() {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        if !QUEUED {
            ck_usb_receive(EP_HID);
        }
    });
}
pub unsafe fn ck_hid_io_send(report: *const u8, generation: u32) -> u8 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        u8::from(
            generation == EPOCH
                && !RESET
                && !report.is_null()
                && ck_usb_submit(EP_HID_IN, report, 64, 0) == 1,
        )
    })
}
