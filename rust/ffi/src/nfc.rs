// SPDX-License-Identifier: Apache-2.0
//! NFC facade: IRQ-local bus/WTX state is disjoint from main-loop Link/Core.
//! NFC and USB are mutually exclusive operating modes and share CCID's response
//! allocation for APDU RX/TX. No borrow of IRQ state crosses a Core call.
use canokey_protocol::nfc::Packet;
use canokey_rust_core::runtime::{
    nfc::{Event, Link},
    nfc_io::{Chip, Io},
};
unsafe extern "C" {
    fn ck_nfc_io_lock() -> u32;
    fn ck_nfc_io_unlock(mask: u32);
    fn ck_nfc_io_read(address: u16, out: *mut u8, length: u8) -> i32;
    fn ck_nfc_io_write(address: u16, bytes: *const u8, length: u8) -> i32;
    fn ck_nfc_io_now() -> u32;
    fn ck_nfc_io_select(active: u8);
    fn ck_nfc_io_delay(milliseconds: u16);
    fn ck_nfc_io_schedule(callback: Option<unsafe extern "C" fn()>, milliseconds: u16);
    fn ck_ccid_response_buffer() -> *mut u8;
    fn ck_core_reset();
    fn ck_core_exchange(
        owner: u8,
        input: *const u8,
        length: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn usb_device_deinit();
}
struct Hardware;
impl Chip for Hardware {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool {
        let Ok(n) = u8::try_from(out.len()) else {
            return false;
        };
        unsafe { ck_nfc_io_read(address, out.as_mut_ptr(), n) == 0 }
    }
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
        let Ok(n) = u8::try_from(bytes.len()) else {
            return false;
        };
        unsafe { ck_nfc_io_write(address, bytes.as_ptr(), n) == 0 }
    }
}
impl canokey_rust_core::runtime::nfc_provision::Provision for Hardware {
    fn select(&mut self, active: bool) {
        unsafe { ck_nfc_io_select(active as u8) }
    }
    fn delay_ms(&mut self, milliseconds: u16) {
        unsafe { ck_nfc_io_delay(milliseconds) }
    }
}
/// Boot-only, before GPIO NFC IRQ is enabled. EEPROM delays require SysTick.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_nfc_configure() -> i32 {
    if canokey_rust_core::runtime::nfc_provision::configure(&mut Hardware) {
        0
    } else {
        -1
    }
}
static mut ACTIVE: bool = false;
static mut IO: Io = Io::new(0);
static mut LINK: Link = Link::new();
static mut GENERATION: u32 = 0;
static mut PENDING: bool = false;
static mut LENGTH: usize = 0;
static mut SENT: usize = 0;
static mut MORE: bool = false;
static mut FIDO: bool = false;
unsafe fn with_io<T>(f: impl FnOnce(&mut Io, &mut Hardware, u32) -> T) -> T {
    unsafe {
        let mask = ck_nfc_io_lock();
        let result = f(
            &mut *core::ptr::addr_of_mut!(IO),
            &mut Hardware,
            ck_nfc_io_now(),
        );
        ck_nfc_io_unlock(mask);
        result
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn is_nfc() -> u8 {
    unsafe { ACTIVE as u8 }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_nfc_progress() -> u8 {
    unsafe { with_io(|io, _, _| io.live() as u8) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfc_handler() {
    unsafe {
        with_io(|io, chip, now| {
            if ACTIVE {
                io.interrupt(now, chip);
            } else {
                let _ = chip.read(0xfff7, &mut [0; 3]);
            }
        });
    }
}
unsafe extern "C" fn timer() {
    unsafe {
        with_io(|io, chip, now| {
            if ACTIVE {
                io.tick(now, chip);
                if io.live() {
                    ck_nfc_io_schedule(Some(timer), 150);
                }
            }
        });
    }
}
unsafe fn reset_link() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(LINK)).reset();
        PENDING = false;
        LENGTH = 0;
        SENT = 0;
        MORE = false;
        FIDO = false;
        ck_core_reset();
    }
}
/// Boot-only mode latch, before any transport or applet is started.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_nfc_set_mode(active: u8) {
    unsafe {
        ACTIVE = active != 0;
    }
}
/// Main-loop startup only. Quiesce USB before leasing its byte allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfc_init() {
    unsafe {
        usb_device_deinit();
        let mask = ck_nfc_io_lock();
        ck_nfc_io_schedule(None, 0);
        ACTIVE = true;
        IO = Io::new(ck_nfc_io_now());
        GENERATION = 0;
        ck_nfc_io_unlock(mask);
        reset_link();
        with_io(|io, chip, now| io.poll(now, false, chip));
    }
}
unsafe fn fault() {
    unsafe {
        with_io(|io, _, _| {
            if io.generation() == GENERATION {
                io.fault();
            }
        });
    }
}
unsafe fn send(packet: &Packet) -> bool {
    unsafe { with_io(|io, chip, _| io.generation() == GENERATION && io.send(packet, chip)) }
}
unsafe fn execute(input: *const u8, length: usize, aggregate: bool) {
    unsafe {
        let started = with_io(|io, _, now| {
            if io.generation() != GENERATION || !io.begin_execution(now) {
                return false;
            }
            ck_nfc_io_schedule(Some(timer), 150);
            true
        });
        if !started {
            return;
        }
        let buffer = ck_ccid_response_buffer();
        let n = ck_core_exchange(4, input, length, buffer, 258);
        with_io(|io, _, now| {
            ck_nfc_io_schedule(None, 0);
            io.computed(now);
        });
        let n = if n < 2 {
            *buffer = 0x6f;
            *buffer.add(1) = 0;
            2
        } else {
            n as usize
        };
        if n > 258 {
            fault();
            return;
        }
        MORE = aggregate && *buffer.add(n - 2) == 0x61;
        LENGTH = if MORE { n - 2 } else { n };
        SENT = 0;
        PENDING = true;
    }
}
unsafe fn next_response() {
    unsafe {
        if SENT == LENGTH && MORE {
            // The existing engine owns response sources/offsets. This request
            // merely continues its stream; no NFC-specific APDU engine exists.
            const GET_RESPONSE: [u8; 5] = [0, 0xc0, 0, 0, 0];
            execute(GET_RESPONSE.as_ptr(), GET_RESPONSE.len(), true);
            return;
        }
        let buffer = ck_ccid_response_buffer();
        let remaining = core::slice::from_raw_parts(buffer.add(SENT), LENGTH - SENT);
        match (&mut *core::ptr::addr_of_mut!(LINK)).response(remaining, MORE) {
            Ok(packet) => {
                if send(&packet) {
                    match (&mut *core::ptr::addr_of_mut!(LINK)).sent() {
                        Ok(n) => SENT += n,
                        Err(_) => fault(),
                    }
                } else {
                    fault();
                }
            }
            Err(_) => fault(),
        }
    }
}
// Keep the packet window off the applet/crypto call path.
#[inline(never)]
unsafe fn receive() -> Option<Result<Event, canokey_rust_core::runtime::nfc::Error>> {
    unsafe {
        let mut frame = [0; 32];
        let n = with_io(|io, _, _| {
            if io.generation() != GENERATION {
                None
            } else {
                io.take(&mut frame)
            }
        })?;
        let buffer = ck_ccid_response_buffer();
        Some(
            (&mut *core::ptr::addr_of_mut!(LINK))
                .receive(&frame[..n], core::slice::from_raw_parts_mut(buffer, 261)),
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfc_loop() {
    unsafe {
        if !ACTIVE {
            return;
        }
        let dirty = (&*core::ptr::addr_of!(LINK)).dirty() || PENDING;
        let generation = with_io(|io, chip, now| {
            io.poll(now, dirty, chip);
            io.generation()
        });
        if generation != GENERATION {
            GENERATION = generation;
            reset_link();
            return;
        }
        if PENDING {
            match with_io(|io, _, _| io.complete_execution()) {
                None => return,
                Some(false) => {
                    reset_link();
                    return;
                }
                Some(true) => {
                    PENDING = false;
                    next_response();
                    return;
                }
            }
        }
        let Some(event) = receive() else {
            return;
        };
        let buffer = ck_ccid_response_buffer();
        match event {
            Ok(Event::Execute(length)) => {
                let input = core::slice::from_raw_parts(buffer, length);
                if length >= 5 && input[..4] == [0, 0xa4, 4, 0] {
                    FIDO = length == 13
                        && input[4] == 8
                        && input[5..] == [0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1];
                }
                let aggregate = FIDO && length >= 7 && input[4] == 0;
                execute(buffer, length, aggregate);
            }
            Ok(Event::Send(packet)) => {
                if !send(&packet) {
                    fault();
                }
            }
            Ok(Event::NextResponse) => next_response(),
            Ok(Event::Deselect) => {
                if !send(&Packet::deselect()) {
                    fault();
                }
                reset_link();
            }
            Ok(Event::Waiting(_)) | Err(_) => fault(),
        }
    }
}

/// Boot-only stored NFC disable policy, before GPIO IRQ is enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_nfc_silence() -> i32 {
    if Hardware.write(0xffe6, &[0x33]) {
        0
    } else {
        -1
    }
}
