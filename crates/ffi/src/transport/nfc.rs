// SPDX-License-Identifier: Apache-2.0
//! NFC facade: IRQ-local bus/WTX state is disjoint from main-loop Link/Core.
//! NFC and USB are mutually exclusive operating modes and share CCID's response
//! allocation for APDU RX/TX. No borrow of IRQ state crosses a Core call.
#[cfg(test)]
pub(crate) mod tests;
use crate::composition::Provider;
#[cfg(not(test))]
use crate::composition::core::{exchange as ck_core_exchange, reset as ck_core_reset};
use crate::sys::ck_nfc_io_delay;
use crate::sys::ck_nfc_io_lock;
use crate::sys::ck_nfc_io_now;
use crate::sys::ck_nfc_io_read;
use crate::sys::ck_nfc_io_schedule;
use crate::sys::ck_nfc_io_select;
use crate::sys::ck_nfc_io_unlock;
use crate::sys::ck_nfc_io_write;
#[cfg(not(test))]
use crate::transport::usb::deinit;
use canokey_protocol::response::StatusWord as Sw;
use canokey_protocol::{
    apdu,
    nfc::{self as wire, Packet},
};
use canokey_rust_core::runtime::nfc::request::{Backend as ReceiveBackend, Rejection, Request};
use canokey_rust_core::runtime::{
    nfc::{Event, Link},
    nfc_io::{Chip, Io},
};
#[cfg(test)]
use tests::deinit;
#[cfg(test)]
unsafe fn ck_core_reset<P: Provider>() {
    unsafe { tests::ck_core_reset() }
}
#[cfg(test)]
unsafe fn ck_core_exchange<P: Provider>(
    owner: u8,
    input: *const u8,
    length: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    unsafe { tests::ck_core_exchange(owner, input, length, out, capacity) }
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
pub unsafe fn ck_nfc_configure() -> i32 {
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
static mut REQUEST: Request = Request::new();
static mut BUDGET: u32 = 0;
struct Stager<P>(core::marker::PhantomData<P>);
impl<P: Provider> ReceiveBackend for Stager<P> {
    fn prepare(&mut self, prefix: &[u8; apdu::EXTENDED_HEADER_BYTES]) -> Result<(), Rejection> {
        #[cfg(test)]
        {
            tests::prepare(prefix)
        }
        #[cfg(not(test))]
        {
            let limit = unsafe {
                crate::composition::core::with_core::<P, _>(|core, p| core.prepare_nfc(prefix, p))
            }
            .map_err(Rejection::Status)?;
            let body = usize::from(u16::from_be_bytes([prefix[5], prefix[6]]));
            if body > limit as usize {
                return Err(Rejection::TooLarge);
            }
            #[cfg(feature = "ctap")]
            if body <= crate::transport::pke_scratch::capacity::<P>()
                && crate::transport::pke_scratch::acquire::<P>()
            {
                return Ok(());
            }
            Err(Rejection::Status(Sw::UNABLE_TO_PROCESS))
        }
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
        #[cfg(test)]
        {
            tests::stage_write(offset, bytes)
        }
        #[cfg(all(not(test), feature = "ctap"))]
        {
            crate::transport::pke_scratch::write::<P>(offset, bytes)
        }
        #[cfg(all(not(test), not(feature = "ctap")))]
        {
            let _ = (offset, bytes);
            false
        }
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool {
        #[cfg(test)]
        {
            tests::stage_read(offset, out)
        }
        #[cfg(all(not(test), feature = "ctap"))]
        {
            crate::transport::pke_scratch::read::<P>(offset, out)
        }
        #[cfg(all(not(test), not(feature = "ctap")))]
        {
            let _ = (offset, out);
            false
        }
    }
    fn close(&mut self) {
        #[cfg(test)]
        tests::stage_close();
        #[cfg(all(not(test), feature = "ctap"))]
        crate::transport::pke_scratch::close_acquired::<P>();
    }
}
struct Outcome {
    length: i32,
    info: Option<apdu::CommandInfo>,
    fido: bool,
}
#[cfg(not(test))]
unsafe fn dispatch<P: Provider>(request: &mut Request, buffer: *mut u8) -> Outcome {
    use canokey_rust_core::runtime::engine::{InputSource, Reply};
    struct Source<'a, P: Provider> {
        request: &'a mut Request,
        inline: &'a [u8],
        backend: Stager<P>,
        offset: usize,
    }
    impl<P: Provider> InputSource for Source<'_, P> {
        fn read(&mut self, out: &mut [u8]) -> Result<usize, Sw> {
            if !execution_live() {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            if !self
                .request
                .read(self.offset, out, self.inline, &mut self.backend)
                || !execution_live()
            {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            self.offset += out.len();
            Ok(out.len())
        }
        fn close(&mut self) -> Result<(), Sw> {
            self.request.reset(&mut self.backend);
            // IRQs can cancel while parsing or wiping/releasing PKE. Check
            // after cleanup, including after the last successful source read.
            if execution_live() {
                Ok(())
            } else {
                Err(Sw::UNABLE_TO_PROCESS)
            }
        }
    }
    unsafe {
        crate::composition::core::with_core::<P, _>(|core, p| {
            let result = request.finish(&mut Stager::<P>(core::marker::PhantomData));
            let (reply, info) = match result {
                Ok(()) => {
                    let total = request.len();
                    core.receive_source_with_info(
                        crate::transport::owners::OWNER_NFC,
                        total,
                        &mut Source::<P> {
                            request,
                            inline: core::slice::from_raw_parts(buffer, apdu::SHORT_FRAME_BYTES),
                            backend: Stager(core::marker::PhantomData),
                            offset: 0,
                        },
                        p,
                    )
                }
                Err(rejection) => {
                    let malformed = request.is_malformed();
                    request.reset(&mut Stager::<P>(core::marker::PhantomData));
                    if malformed {
                        core.abort_request(crate::transport::owners::OWNER_NFC, p);
                    }
                    match rejection {
                        Rejection::Status(sw) => (Reply::Status(sw), None),
                        Rejection::TooLarge => {
                            buffer.write(0x39); // CTAP2_ERR_REQUEST_TOO_LARGE.
                            buffer.add(1).write(0x90);
                            buffer.add(2).write(0);
                            return Outcome {
                                length: 3,
                                info: None,
                                fido: false,
                            };
                        }
                    }
                }
            };
            let fido = core.fido_selected(p);
            let length = core
                .transmit(
                    reply,
                    core::slice::from_raw_parts_mut(buffer, apdu::SHORT_REPLY_BYTES),
                    p,
                )
                .map_or(-1, |n| n as i32);
            Outcome { length, info, fido }
        })
    }
}
#[cfg(test)]
unsafe fn dispatch<P: Provider>(request: &mut Request, buffer: *mut u8) -> Outcome {
    unsafe { tests::dispatch::<P>(request, buffer) }
}
#[cfg(not(test))]
fn execution_live() -> bool {
    unsafe { with_io(|io, _, _| io.generation() == GENERATION && io.live()) }
}
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
pub unsafe fn is_nfc() -> u8 {
    unsafe { ACTIVE as u8 }
}
pub unsafe extern "C" fn ck_nfc_progress() -> u8 {
    unsafe { with_io(|io, _, _| io.live() as u8) }
}
pub unsafe fn nfc_handler() {
    unsafe {
        with_io(|io, chip, now| {
            if ACTIVE {
                io.interrupt(now, chip);
            } else {
                let _ = chip.read(wire::FM_REG_MAIN_IRQ, &mut [0; wire::FM_IRQ_BYTES]);
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
                    ck_nfc_io_schedule(Some(timer), wire::WTX_INTERVAL_MS);
                }
            }
        });
    }
}
unsafe fn reset_link<P: Provider>() {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(LINK)).reset();
        PENDING = false;
        LENGTH = 0;
        SENT = 0;
        MORE = false;
        BUDGET = 0;
        (&mut *core::ptr::addr_of_mut!(REQUEST)).reset(&mut Stager::<P>(core::marker::PhantomData));
        ck_core_reset::<P>();
    }
}
/// Boot-only mode latch, before any transport or applet is started.
pub unsafe fn ck_nfc_set_mode(active: u8) {
    unsafe {
        ACTIVE = active != 0;
    }
}
/// Main-loop startup only. Quiesce USB before leasing its byte allocation.
pub unsafe fn init<P: Provider>() {
    unsafe {
        deinit();
        let mask = ck_nfc_io_lock();
        ck_nfc_io_schedule(None, 0);
        ACTIVE = true;
        IO = Io::new(ck_nfc_io_now());
        GENERATION = 0;
        ck_nfc_io_unlock(mask);
        reset_link::<P>();
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
unsafe fn execute<P: Provider>(continuation: Option<&[u8]>) {
    unsafe {
        let started = with_io(|io, _, now| {
            if io.generation() != GENERATION || !io.begin_execution(now) {
                return false;
            }
            ck_nfc_io_schedule(Some(timer), wire::WTX_INTERVAL_MS);
            true
        });
        if !started {
            return;
        }
        let buffer = crate::transport::ccid::ck_ccid_response_buffer();
        use crate::transport::owners::OWNER_NFC;
        let n = if let Some(input) = continuation {
            ck_core_exchange::<P>(
                OWNER_NFC,
                input.as_ptr(),
                input.len(),
                buffer,
                apdu::SHORT_REPLY_BYTES,
            )
        } else {
            let outcome = dispatch::<P>(&mut *core::ptr::addr_of_mut!(REQUEST), buffer);
            BUDGET = outcome
                .info
                .filter(|info| outcome.fido && info.extended)
                .map_or(0, |info| info.le.unwrap_or(65536));
            outcome.length
        };
        with_io(|io, _, now| {
            ck_nfc_io_schedule(None, 0);
            io.computed(now);
        });
        let n = if n < 2 {
            // Transport failure synthesizes SW 0x6F00; no valid Core response exists.
            *buffer = 0x6f;
            *buffer.add(1) = 0;
            2
        } else {
            n as usize
        };
        if n > apdu::SHORT_REPLY_BYTES {
            fault();
            return;
        }
        BUDGET -= BUDGET.min((n - 2) as u32);
        MORE = BUDGET != 0 && *buffer.add(n - 2) == apdu::MORE_DATA_SW1;
        LENGTH = if MORE { n - 2 } else { n };
        SENT = 0;
        PENDING = true;
    }
}
unsafe fn next_response<P: Provider>() {
    unsafe {
        if SENT == LENGTH && MORE {
            // The existing engine owns response sources/offsets. This request
            // merely continues its stream; no NFC-specific APDU engine exists.
            let mut command = apdu::GET_RESPONSE;
            command[4] = BUDGET.min(256) as u8;
            execute::<P>(Some(&command));
            return;
        }
        let buffer = crate::transport::ccid::ck_ccid_response_buffer();
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
unsafe fn receive<P: Provider>() -> Option<Result<Event, canokey_rust_core::runtime::nfc::Error>> {
    unsafe {
        let mut frame = [0; wire::FRAME_LIMIT];
        let n = with_io(|io, _, _| {
            if io.generation() != GENERATION {
                None
            } else {
                io.take(&mut frame)
            }
        })?;
        let buffer = crate::transport::ccid::ck_ccid_response_buffer();
        Some(
            (&mut *core::ptr::addr_of_mut!(LINK)).receive_with(&frame[..n], |offset, bytes| {
                let request = &mut *core::ptr::addr_of_mut!(REQUEST);
                if request.len() != offset {
                    return Err(canokey_rust_core::runtime::nfc::Error::Sequence);
                }
                request.append(
                    bytes,
                    core::slice::from_raw_parts_mut(buffer, apdu::SHORT_FRAME_BYTES),
                    &mut Stager::<P>(core::marker::PhantomData),
                );
                Ok(())
            }),
        )
    }
}
pub unsafe fn poll<P: Provider>() {
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
            reset_link::<P>();
            return;
        }
        if PENDING {
            match with_io(|io, _, _| io.complete_execution()) {
                None => return,
                Some(false) => {
                    reset_link::<P>();
                    return;
                }
                Some(true) => {
                    PENDING = false;
                    next_response::<P>();
                    return;
                }
            }
        }
        let Some(event) = receive::<P>() else {
            return;
        };
        match event {
            Ok(Event::Execute(_)) => execute::<P>(None),
            Ok(Event::Send(packet)) => {
                if !send(&packet) {
                    fault();
                }
            }
            Ok(Event::NextResponse) => next_response::<P>(),
            Ok(Event::Ignored) => with_io(|io, _, _| {
                if io.generation() == GENERATION {
                    io.ignored();
                }
            }),
            Ok(Event::Deselect) => {
                if !send(&Packet::deselect()) {
                    fault();
                }
                reset_link::<P>();
            }
            Ok(Event::Waiting(_)) | Err(_) => fault(),
        }
    }
}

/// Boot-only stored NFC disable policy, before GPIO IRQ is enabled.
pub unsafe fn ck_nfc_silence() -> i32 {
    if Hardware.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_SILENCE]) {
        0
    } else {
        -1
    }
}
