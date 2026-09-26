// SPDX-License-Identifier: Apache-2.0
//! Serialized CCID entrypoint. IRQs operate only the platform packet mailbox.
use canokey_rust_core::runtime::ccid::{Backend, Request, Scratch, Transport};

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
static mut RESPONSE: [u8; 10 + canokey_rust_core::runtime::ccid::REPLY] =
    [0; 10 + canokey_rust_core::runtime::ccid::REPLY];
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
    fn ck_hid_busy() -> u8;
    fn ck_hid_active() -> u8;
    fn pke_buffer_size() -> usize;
    fn pke_buffer_acquire(owner: u8) -> i32;
    fn pke_buffer_release(owner: u8) -> i32;
    fn pke_buffer_clear() -> i32;
    fn pke_buffer_read(offset: usize, out: *mut u8, length: usize) -> i32;
    fn pke_buffer_write(offset: usize, input: *const u8, length: usize) -> i32;
}
struct Platform {
    generation: u32,
}
impl Scratch for Platform {
    fn acquire(&mut self, length: usize) -> bool {
        #[cfg(feature = "ctap")]
        unsafe {
            length <= pke_buffer_size() && pke_buffer_acquire(3) == 0
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = length;
            false
        }
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool {
        #[cfg(feature = "ctap")]
        unsafe {
            pke_buffer_read(offset, out.as_mut_ptr(), out.len()) == 0
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (offset, out);
            false
        }
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
        #[cfg(feature = "ctap")]
        unsafe {
            pke_buffer_write(offset, bytes.as_ptr(), bytes.len()) == 0
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (offset, bytes);
            false
        }
    }
    fn close(&mut self) {
        #[cfg(feature = "ctap")]
        unsafe {
            assert_eq!(pke_buffer_clear(), 0);
            assert_eq!(pke_buffer_release(3), 0);
        }
    }
}
impl Backend for Platform {
    fn now(&mut self) -> u32 {
        unsafe { ck_ccid_io_now() }
    }
    fn reset(&mut self) {
        unsafe { super::entrypoints::ck_core_reset() }
    }
    fn prepare_extended(&mut self, prefix: &[u8; 7], total: usize) -> Result<u16, u16> {
        #[cfg(feature = "ctap")]
        {
            super::entrypoints::with_core(|core, p| {
                core.prepare_extended(1, prefix, total, p)
                    .map_err(|sw| sw.value())
            })
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = (prefix, total);
            Err(0x6700)
        }
    }
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
            return super::entrypoints::with_core(|core, p| {
                let total = request.len();
                let reply = core.receive_source(
                    1,
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
            super::entrypoints::ck_core_exchange(
                1,
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
                        && super::entrypoints::can_preempt())),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_scratch_busy() -> u8 {
    unsafe { u8::from(ccid().scratch_busy()) }
}
// The USB receive window is dead before applet/crypto execution starts.
#[inline(never)]
unsafe fn receive_packet(transport: &mut Transport, platform: &mut Platform) -> bool {
    let mut packet = [0; 64];
    let mut tick = 0;
    let n = unsafe { ck_ccid_io_take(platform.generation, packet.as_mut_ptr(), &mut tick) };
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
        if super::nfc::is_nfc() != 0 {
            return;
        }
        #[cfg(feature = "usb-webusb")]
        if super::webusb_link::block_competitor()
            && !super::webusb_link::try_preempt(matches!(ck_ccid_io_peek(), 0x62 | 0x63 | 0x6f))
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
        if transport.can_receive() && !receive_packet(transport, &mut platform) {
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
            let mut packet = [0; 10];
            if !super::ccid_io::take_presence(generation, &mut packet) {
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
