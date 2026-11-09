// SPDX-License-Identifier: Apache-2.0
//! Serialized CCID entrypoint. IRQs operate only the platform packet mailbox.
#[cfg(all(feature = "ctap", feature = "usb-hid"))]
use crate::transport::hid::link::ck_hid_busy;
use canokey_protocol::ccid::HEADER;
use canokey_rust_core::runtime::ccid::{Backend, Transport};

use crate::composition::{Provider, core as core_ops};
use crate::transport::owners::OWNER_CCID;

crate::lazy_state!(
    CCID,
    CCID_READY,
    Transport,
    Transport::new(),
    initialize_ccid,
    ccid
);
static mut GENERATION: u32 = u32::MAX;
// Endpoint-owned bytes are outside Transport. Polling/timeout may mutably
// borrow Transport while the USB IRQ reads this buffer through its TX lease.
const RESPONSE_BYTES: usize = HEADER + canokey_rust_core::runtime::ccid::REPLY;
// WebUSB receives its bounded envelope here before entering Core, so a new
// SETUP can abort partial RX without modifying the previous APDU context.
#[cfg(feature = "usb-webusb")]
pub(crate) const SHARED_IO_BYTES: usize = canokey_rust_core::runtime::webusb::COMMAND_LIMIT;
#[cfg(not(feature = "usb-webusb"))]
pub(crate) const SHARED_IO_BYTES: usize = RESPONSE_BYTES;
const _: () = assert!(SHARED_IO_BYTES >= RESPONSE_BYTES);
#[repr(C)]
struct SharedIo {
    response: [u8; RESPONSE_BYTES],
    envelope_tail: [u8; SHARED_IO_BYTES - RESPONSE_BYTES],
}
static mut RESPONSE: SharedIo = SharedIo {
    response: [0; RESPONSE_BYTES],
    envelope_tail: [0; SHARED_IO_BYTES - RESPONSE_BYTES],
};
// Passive status/parameter replies and refused commands remain live while
// WebUSB owns SharedIo. Endpoint completion protects this small TX lease too.
static mut CONTROL_RESPONSE: [u8; canokey_rust_core::runtime::ccid::CONTROL_REPLY] =
    [0; canokey_rust_core::runtime::ccid::CONTROL_REPLY];
use self::io::{
    ck_ccid_io_arm, ck_ccid_io_disarm, ck_ccid_io_generation, ck_ccid_io_idle, ck_ccid_io_peek,
    ck_ccid_io_pending, ck_ccid_io_submit, ck_ccid_io_take,
};
#[cfg(all(feature = "ctap", not(feature = "usb-hid")))]
unsafe extern "C" {
    fn ck_hid_busy() -> u8;
}
// Constructed only by serialized main-loop poll/progress. Backend execution
// never overlaps a live Core borrow; progress only services transport mailboxes.
struct Platform<P> {
    generation: u32,
    provider: core::marker::PhantomData<P>,
}
impl<P: Provider> Backend for Platform<P> {
    fn abort_input(&mut self) {
        unreachable!("buffered CCID never lends application input");
    }
    fn admit(&mut self) -> bool {
        // The shared receiver calls this only after a complete, valid
        // bounded XfrBlock header. Fragmented headers therefore cannot
        // reserve early or skip foreign-owner admission on completion.
        if hid_busy() {
            return false;
        }
        #[cfg(feature = "usb-webusb")]
        unsafe {
            !crate::transport::webusb::block_competitor()
                || crate::transport::webusb::try_preempt::<P>(true, false)
        }
        #[cfg(not(feature = "usb-webusb"))]
        {
            true
        }
    }
    fn reset(&mut self) {
        unsafe { core_ops::reset::<P>() }
    }
    fn slot_power(&mut self) -> bool {
        unsafe {
            // Power commands validate their complete envelope before reset.
            // A refused reset preserves foreign selection and continuations.
            #[cfg(feature = "usb-webusb")]
            if crate::transport::webusb::block_competitor()
                && !crate::transport::webusb::try_preempt::<P>(true, false)
            {
                return false;
            }
            core_ops::slot_power::<P>();
            true
        }
    }
    fn exchange(&mut self, request: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let input = request;
        let n = unsafe {
            core_ops::exchange::<P>(
                OWNER_CCID,
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        if n < 0 { Err(()) } else { Ok(n as usize) }
    }
    fn arm(&mut self, bytes: &[u8; 10], interval: u16) {
        unsafe { ck_ccid_io_arm(self.generation, bytes.as_ptr(), bytes.len() as u8, interval) }
    }
    fn disarm(&mut self) {
        unsafe { ck_ccid_io_disarm() }
    }
}
fn hid_busy() -> bool {
    #[cfg(feature = "ctap")]
    unsafe {
        ck_hid_busy() != 0
    }
    #[cfg(not(feature = "ctap"))]
    {
        false
    }
}
pub unsafe extern "C" fn ck_ccid_idle() -> u8 {
    unsafe {
        if hid_busy() {
            return 1;
        }
        u8::from(
            GENERATION == ck_ccid_io_generation()
                && ck_ccid_io_pending() == 0
                && ck_ccid_io_idle() != 0
                && ccid().completed_transaction()
                && core_ops::can_preempt(),
        )
    }
}
#[cfg(feature = "usb-keyboard")]
pub unsafe fn ck_ccid_scratch_busy() -> u8 {
    0
}
// The USB receive window is dead before applet/crypto execution starts.
#[inline(never)]
unsafe fn receive_packet<P: Provider>(
    transport: &mut Transport,
    platform: &mut Platform<P>,
    pending: bool,
) -> bool {
    let mut packet = [0; 64];
    let mut tick = 0;
    // Only consume the packet whose command was admitted by the caller's peek.
    // An IRQ can enqueue a TRANSFER after an empty peek; taking that new packet
    // would bypass HID ownership.
    let n = if pending {
        unsafe { ck_ccid_io_take(platform.generation, packet.as_mut_ptr(), &mut tick) }
    } else {
        0
    };
    if n < 0 {
        return false;
    }
    if n > 0 {
        transport.receive_at(&packet[..n as usize], tick, platform);
    }
    true
}
/// Serialized reset service, including while USB is not yet configured.
pub(crate) unsafe fn service_reset<P: Provider>() -> bool {
    unsafe {
        let generation = ck_ccid_io_generation();
        if GENERATION == generation {
            return false;
        }
        ccid().reset(&mut Platform::<P> {
            generation,
            provider: core::marker::PhantomData,
        });
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(RESPONSE).cast::<u8>(),
            0,
            SHARED_IO_BYTES,
        );
        GENERATION = generation;
        true
    }
}
pub unsafe fn poll<P: Provider>() {
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return;
        }
        if service_reset::<P>() {
            return;
        }
        // Retire endpoint completion before WebUSB tests CCID admission. A new
        // EP0 reservation cannot prevent bookkeeping for an already sent reply.
        if ck_ccid_io_idle() != 0 {
            ccid().completed();
        }
        let generation = ck_ccid_io_generation();
        let mut platform = Platform::<P> {
            generation,
            provider: core::marker::PhantomData,
        };
        let transport = ccid();
        // Foreign HID RX/TX or a retained MSG source permits only independent
        // control replies and refused-body drain, never shared APDU execution.
        let busy = hid_busy();
        let first = ck_ccid_io_peek();
        if ck_ccid_io_idle() != 0 {
            transport.completed();
        }
        if transport.can_receive() && !receive_packet(transport, &mut platform, first >= 0) {
            return;
        }

        // Consume the mailbox's arrival tick before applying main-loop time:
        // delayed polling must not expire a continuation that arrived on time.
        transport.timeout(io::now(), &mut platform);
        if generation != ck_ccid_io_generation() {
            return;
        }
        let (output, capacity) = if transport.needs_apdu_buffer() {
            (
                core::ptr::addr_of_mut!(RESPONSE).cast::<u8>(),
                RESPONSE_BYTES,
            )
        } else {
            (
                core::ptr::addr_of_mut!(CONTROL_RESPONSE).cast::<u8>(),
                canokey_rust_core::runtime::ccid::CONTROL_REPLY,
            )
        };
        if transport.queued() {
            transport.execute(
                busy,
                &mut platform,
                core::slice::from_raw_parts_mut(output, capacity),
            );
        }
        if generation != ck_ccid_io_generation() {
            return;
        }
        if let Some(reply) = transport.reply(core::slice::from_raw_parts(output, capacity)) {
            if ck_ccid_io_submit(
                generation,
                reply.as_ptr(),
                reply.len() as u16,
                u8::from(reply.len() % 64 == 0),
            ) == 1
            {
                transport.submitted();
            }
        }
    }
}

#[cfg(any(feature = "usb-webusb", feature = "nfc"))]
pub fn ck_ccid_response_buffer() -> *mut u8 {
    core::ptr::addr_of_mut!(RESPONSE).cast()
}

/// Called only from HID execution, when no CCID borrow is outstanding.
/// Never reset on generation change, consume APDUs/power commands, expire a
/// session or touch the shared workspace. Slot replies use the independent control TX buffer.
#[cfg(all(feature = "usb-device", feature = "usb-hid"))]
#[cfg_attr(test, allow(dead_code))]
pub unsafe fn presence_progress<P: Provider>() {
    unsafe {
        let generation = ck_ccid_io_generation();
        if GENERATION != generation || ck_ccid_io_idle() == 0 {
            return;
        }
        let transport = ccid();
        transport.completed();
        let mut platform = Platform::<P> {
            generation,
            provider: core::marker::PhantomData,
        };
        if transport.completed_transaction() {
            let mut packet = [0; HEADER];
            if !crate::transport::ccid::io::take_presence(generation, &mut packet) {
                return;
            }
            transport.receive_at(&packet, 0, &mut platform);
            // take_presence admits only bodyless SLOT_STATUS: execute cannot
            // invoke the backend's reset, exchange or scratch operations.
            transport.execute(
                true,
                &mut platform,
                &mut *core::ptr::addr_of_mut!(CONTROL_RESPONSE),
            );
        }
        if transport.presence_reply() {
            if let Some(reply) = transport.reply(&*core::ptr::addr_of!(CONTROL_RESPONSE)) {
                if ck_ccid_io_submit(generation, reply.as_ptr(), reply.len() as u16, 0) == 1 {
                    transport.submitted();
                }
            }
        }
    }
}

pub(crate) mod io;
