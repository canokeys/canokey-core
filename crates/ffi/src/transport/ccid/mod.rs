// SPDX-License-Identifier: Apache-2.0
//! Serialized CCID entrypoint. IRQs operate only the platform packet mailbox.
#[cfg(all(feature = "ctap", feature = "usb-hid"))]
use crate::transport::hid::link::{ck_hid_active, ck_hid_busy};
use canokey_protocol::{apdu::EXTENDED_HEADER_BYTES, ccid::HEADER};
use canokey_rust_core::runtime::ccid::{Backend, Request, Scratch, Transport};

use crate::transport::owners::OWNER_CCID;
#[cfg(feature = "ctap")]
use crate::transport::pke_scratch as pke;

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
static mut RESPONSE: [u8; HEADER + canokey_rust_core::runtime::ccid::REPLY] =
    [0; HEADER + canokey_rust_core::runtime::ccid::REPLY];
unsafe extern "C" {
    fn ck_ccid_io_generation() -> u32;
    fn ck_ccid_io_now() -> u32;
    fn ck_ccid_io_pending() -> u8;
    fn ck_ccid_io_peek() -> i32;
    fn ck_ccid_io_take(generation: u32, output: *mut u8, tick: *mut u32) -> i32;
    fn ck_ccid_io_idle() -> u8;
    fn ck_ccid_io_submit(generation: u32, bytes: *const u8, length: u16, zlp: u8) -> i32;
    fn ck_ccid_io_arm(generation: u32, bytes: *const u8, length: u8, interval: u16);
    fn ck_ccid_io_disarm();
}
#[cfg(feature = "ctap")]
unsafe extern "C" {
    #[cfg(not(feature = "usb-hid"))]
    fn ck_hid_busy() -> u8;
    #[cfg(not(feature = "usb-hid"))]
    fn ck_hid_active() -> u8;
}
struct Platform {
    generation: u32,
}
impl Scratch for Platform {
    fn acquire(&mut self, length: usize) -> bool {
        #[cfg(feature = "ctap")]
        {
            length <= pke::capacity() && pke::acquire()
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = length;
            false
        }
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool {
        #[cfg(feature = "ctap")]
        {
            pke::read(offset, out)
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (offset, out);
            false
        }
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
        #[cfg(feature = "ctap")]
        {
            pke::write(offset, bytes)
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (offset, bytes);
            false
        }
    }
    fn close(&mut self) {
        #[cfg(feature = "ctap")]
        pke::close_acquired();
    }
}
impl Backend for Platform {
    fn now(&mut self) -> u32 {
        unsafe { ck_ccid_io_now() }
    }
    fn reset(&mut self) {
        unsafe { crate::abi::core::ck_core_reset() }
    }
    fn slot_power(&mut self) {
        unsafe { crate::abi::core::ck_core_slot_power() }
    }
    fn prepare_extended(
        &mut self,
        prefix: &[u8; EXTENDED_HEADER_BYTES],
        total: usize,
    ) -> Result<u16, u16> {
        #[cfg(feature = "ctap")]
        {
            crate::abi::core::with_core(|core, p| {
                core.prepare_extended(OWNER_CCID, prefix, total, p)
                    .map_err(|sw| sw.value())
            })
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (prefix, total);
            Err(canokey_protocol::response::StatusWord::WRONG_LENGTH.value())
        }
    }
    // Keep the streamed decoder window and APDU dispatch out of the CCID
    // command switch; short and staged requests retain their existing paths.
    #[inline(never)]
    fn exchange(&mut self, request: &mut Request, out: &mut [u8]) -> Result<usize, ()> {
        #[cfg(feature = "ctap")]
        if request.staged() {
            use canokey_protocol::response::StatusWord;
            use canokey_rust_core::runtime::engine::InputSource;
            struct Source<'a> {
                request: &'a mut Request,
                platform: &'a mut Platform,
                offset: usize,
            }
            impl InputSource for Source<'_> {
                fn read(&mut self, out: &mut [u8]) -> Result<usize, StatusWord> {
                    if !self.request.read(self.offset, out, self.platform) {
                        return Err(StatusWord::UNABLE_TO_PROCESS);
                    }
                    self.offset += out.len();
                    Ok(out.len())
                }
                fn close(&mut self) {
                    self.request.close(self.platform);
                }
            }
            return crate::abi::core::with_core(|core, p| {
                let total = request.len();
                let reply = core.receive_source(
                    OWNER_CCID,
                    total,
                    &mut Source {
                        request,
                        platform: self,
                        offset: 0,
                    },
                    p,
                );
                core.transmit(reply, out, p).map_err(|_| ())
            });
        }
        let input = request.short();
        let n = unsafe {
            crate::abi::core::ck_core_exchange(
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_idle() -> u8 {
    unsafe {
        if hid_busy() {
            return 1;
        }
        u8::from(
            GENERATION == ck_ccid_io_generation()
                && ck_ccid_io_pending() == 0
                && (ccid().idle(ck_ccid_io_now())
                    || (ck_ccid_io_idle() != 0
                        && ccid().completed_transaction()
                        && crate::abi::core::can_preempt())),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_scratch_busy() -> u8 {
    unsafe { u8::from(ccid().scratch_busy()) }
}
// The USB receive window is dead before applet/crypto execution starts.
#[inline(never)]
unsafe fn receive_packet(
    transport: &mut Transport,
    platform: &mut Platform,
    pending: bool,
) -> bool {
    let mut packet = [0; 64];
    let mut tick = 0;
    // Only consume the packet whose command was admitted by the caller's peek.
    // An IRQ can enqueue a TRANSFER after an empty peek; taking that new packet
    // would bypass HID ownership, including extended-request preparation.
    let n = if pending {
        unsafe { ck_ccid_io_take(platform.generation, packet.as_mut_ptr(), &mut tick) }
    } else {
        0
    };
    if n < 0 {
        return false;
    }
    if n > 0 {
        transport.receive(
            &packet[..n as usize],
            tick,
            cfg!(feature = "ctap"),
            platform,
        );
    } else {
        transport.timeout(unsafe { ck_ccid_io_now() }, platform);
    }
    true
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CCID_Loop() {
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return;
        }
        #[cfg(feature = "usb-webusb")]
        if crate::transport::webusb::block_competitor()
            && !crate::transport::webusb::try_preempt(matches!(
                // POWER_ON/OFF and XfrBlock (6F), not passive slot polling.
                u8::try_from(ck_ccid_io_peek()).ok(),
                Some(
                    canokey_protocol::ccid::POWER_ON
                        | canokey_protocol::ccid::POWER_OFF
                        | canokey_protocol::ccid::TRANSFER
                )
            ))
        {
            return;
        }
        let generation = ck_ccid_io_generation();
        let mut platform = Platform { generation };
        let transport = ccid();
        if GENERATION != generation {
            transport.reset(&mut platform);
            (&mut *core::ptr::addr_of_mut!(RESPONSE)).fill(0);
            GENERATION = generation;
            return;
        }
        #[cfg(feature = "ctap")]
        if ck_hid_active() != 0 {
            return;
        }
        let busy = hid_busy();
        let first = ck_ccid_io_peek();
        if busy && transport.blocked_by_hid((first >= 0).then_some(first as u8)) {
            return;
        }
        if ck_ccid_io_idle() != 0 {
            transport.completed();
        }
        if transport.can_receive() && !receive_packet(transport, &mut platform, first >= 0) {
            return;
        }

        if generation != ck_ccid_io_generation() {
            return;
        }
        if transport.queued() {
            transport.execute(busy, &mut platform, &mut *core::ptr::addr_of_mut!(RESPONSE));
        }
        if generation != ck_ccid_io_generation() {
            return;
        }
        if let Some(reply) = transport.reply(&*core::ptr::addr_of!(RESPONSE)) {
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
        transport.tx_timeout(ck_ccid_io_now(), &mut platform);
    }
}

#[cfg(any(feature = "usb-webusb", feature = "nfc"))]
#[unsafe(no_mangle)]
pub extern "C" fn ck_ccid_response_buffer() -> *mut u8 {
    core::ptr::addr_of_mut!(RESPONSE).cast()
}

/// Called only from HID execution, when no CCID borrow is outstanding.
/// Never reset on generation change, consume APDUs/power commands, expire a
/// session or touch the shared workspace. Slot replies use the CCID TX buffer.
#[cfg(all(feature = "usb-device", feature = "usb-hid"))]
pub unsafe fn presence_progress() {
    unsafe {
        let generation = ck_ccid_io_generation();
        if GENERATION != generation || ck_ccid_io_idle() == 0 {
            return;
        }
        let transport = ccid();
        transport.completed();
        let mut platform = Platform { generation };
        if transport.completed_transaction() {
            let mut packet = [0; HEADER];
            if !crate::transport::ccid::io::take_presence(generation, &mut packet) {
                return;
            }
            transport.receive(&packet, ck_ccid_io_now(), false, &mut platform);
            // take_presence admits only bodyless SLOT_STATUS: execute cannot
            // invoke the backend's reset, exchange or scratch operations.
            transport.execute(true, &mut platform, &mut *core::ptr::addr_of_mut!(RESPONSE));
        }
        if transport.presence_reply() {
            if let Some(reply) = transport.reply(&*core::ptr::addr_of!(RESPONSE)) {
                if ck_ccid_io_submit(generation, reply.as_ptr(), reply.len() as u16, 0) == 1 {
                    transport.submitted();
                }
            }
        }
    }
}

pub(crate) mod io;

// Keep the fixture swap point's imported and exported ABI signatures checked.
const _: crate::sys::CcidIoTake = ck_ccid_io_take;
