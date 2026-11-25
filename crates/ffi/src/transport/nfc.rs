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
#[cfg(feature = "ctap")]
use canokey_ports::contracts::NFC_UP_LIMIT_MS;
use canokey_protocol::response::StatusWord as Sw;
use canokey_protocol::{
    apdu,
    nfc::{self as wire, Packet},
};
use canokey_rust_core::runtime::nfc::request::{Backend as ReceiveBackend, Rejection, Request};
use canokey_rust_core::runtime::{
    nfc::{Event, Link, Response, ResponseBudget},
    nfc_io::Chip,
};
const FSC: usize = wire::MAX_FRAME_BYTES;
type Io = canokey_rust_core::runtime::nfc_io::Io<'static, FSC>;
#[cfg(test)]
use tests::deinit;
// CTAP status returned inside the NFC APDU for an oversized FIDO request.
#[cfg(not(test))]
const CTAP_REQUEST_TOO_LARGE: u8 = 0x39;
#[cfg(test)]
unsafe fn ck_core_reset<P: Provider>() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
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
    // SAFETY: The serialized fixture forwards the caller's validated input and output buffers.
    unsafe { tests::ck_core_exchange(owner, input, length, out, capacity) }
}
struct Hardware;
impl Chip for Hardware {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool {
        let Ok(n) = u8::try_from(out.len()) else {
            return false;
        };
        // SAFETY: The slice provides the live region for the checked chip I/O byte count.
        unsafe { ck_nfc_io_read(address, out.as_mut_ptr(), n) == 0 }
    }
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool {
        let Ok(n) = u8::try_from(bytes.len()) else {
            return false;
        };
        // SAFETY: The slice provides the live region for the checked chip I/O byte count.
        unsafe { ck_nfc_io_write(address, bytes.as_ptr(), n) == 0 }
    }
}
impl canokey_rust_core::runtime::nfc_provision::Provision for Hardware {
    fn select(&mut self, active: bool) {
        // SAFETY: The NFC chip callbacks are installed; shared chip state is accessed under the NFC I/O lock.
        unsafe { ck_nfc_io_select(active as u8) }
    }
    fn delay_ms(&mut self, milliseconds: u16) {
        // SAFETY: The NFC chip callbacks are installed; shared chip state is accessed under the NFC I/O lock.
        unsafe { ck_nfc_io_delay(milliseconds) }
    }
}
/// Boot-only, before GPIO NFC IRQ is enabled. EEPROM delays require SysTick.
///
/// # Safety
/// Call during boot, before the GPIO NFC IRQ and transport polling can run. SysTick must be available for chip delays.
#[inline(never)]
pub unsafe fn ck_nfc_configure() -> i32 {
    use canokey_rust_core::runtime::nfc_provision;
    if nfc_provision::configure_for::<FSC>(&mut Hardware) {
        0
    } else {
        -1
    }
}
#[repr(C)]
struct NfcState {
    // The boot latch is read by both contexts. Writes take place before
    // IRQ enable or under the NFC I/O lock.
    active: bool,
    // Main-loop-only FIDO UP, owned by the power cycle across link resets.
    #[cfg(feature = "ctap")]
    up_available: bool,
    // The main loop owns the accepted generation and all APDU link state.
    pending: bool,
    more: bool,
    generation: u32,
    length: usize,
    sent: usize,
    budget: ResponseBudget,
    // The main loop, IRQ and WTX timer share chip state under ck_nfc_io_lock.
    io: Io,
    // The main loop owns framing and transient request backing.
    link: Link,
    request: Request,
}

// The mode query and IRQ can run before main-loop polling. Use a boot value
// and borrow only the required field across each call.
static mut NFC_FRAME: [u8; FSC] = [0x00; FSC];
static mut NFC: NfcState = NfcState {
    active: false,
    #[cfg(feature = "ctap")]
    up_available: false,
    pending: false,
    more: false,
    generation: 0,
    length: 0,
    sent: 0,
    budget: ResponseBudget::new(),
    io: Io::new(0, None),
    link: Link::new(),
    request: Request::new(),
};
struct Stager<P>(core::marker::PhantomData<P>);
impl<P: Provider> ReceiveBackend for Stager<P> {
    fn prepare(&mut self, prefix: &[u8; apdu::EXTENDED_HEADER_BYTES]) -> Result<(), Rejection> {
        #[cfg(test)]
        {
            tests::prepare(prefix)
        }
        #[cfg(not(test))]
        {
            // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
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
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        crate::composition::core::with_core::<P, _>(|core, p| {
            let result = request.finish(
                core::slice::from_raw_parts(buffer, apdu::SHORT_FRAME_BYTES),
                &mut Stager::<P>(core::marker::PhantomData),
            );
            let (reply, info) = match result {
                Ok(()) => {
                    let total = request.len();
                    core.receive_source_with_info(
                        canokey_rust_core::runtime::owners::OWNER_NFC,
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
                        core.abort_request(canokey_rust_core::runtime::owners::OWNER_NFC, p);
                    }
                    match rejection {
                        Rejection::Status(sw) => (Reply::Status(sw), None),
                        Rejection::TooLarge => {
                            buffer.write(CTAP_REQUEST_TOO_LARGE);
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
                .map_or(-1, |n| i32::try_from(n).unwrap());
            Outcome { length, info, fido }
        })
    }
}
#[cfg(test)]
unsafe fn dispatch<P: Provider>(request: &mut Request, buffer: *mut u8) -> Outcome {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe { tests::dispatch::<P>(request, buffer) }
}
#[cfg(not(test))]
fn execution_live() -> bool {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe { with_io(|io, _, _| io.generation() == NFC.generation && io.live()) }
}
unsafe fn with_io<T>(f: impl FnOnce(&mut Io, &mut Hardware, u32) -> T) -> T {
    // SAFETY: The NFC chip callbacks are installed; shared chip state is accessed under the NFC I/O lock.
    unsafe {
        let mask = ck_nfc_io_lock();
        let result = f(
            &mut *core::ptr::addr_of_mut!(NFC.io),
            &mut Hardware,
            ck_nfc_io_now(),
        );
        ck_nfc_io_unlock(mask);
        result
    }
}
///
/// # Safety
/// Read the mode after the boot latch is set, or from the serialized code that sets it.
pub unsafe fn is_nfc() -> u8 {
    // SAFETY: The mode latch is set at boot before enabling controller IRQs.
    unsafe { NFC.active as u8 }
}
pub unsafe extern "C" fn ck_nfc_progress() -> u8 {
    // SAFETY: The NFC I/O lock protects the IRQ-owned execution flags until the snapshot is read.
    unsafe { with_io(|io, _, _| io.live() as u8) }
}
/// Consume FIDO UP established by NFC power-on.
///
/// # Safety
/// Call only on the serialized main loop, with the NFC clock callback installed.
#[cfg(feature = "ctap")]
pub unsafe fn take_up() -> bool {
    // SAFETY: Only the main loop owns the flag. The tick is milliseconds since boot.
    unsafe {
        let available = NFC.up_available;
        NFC.up_available = false;
        available && ck_nfc_io_now() < NFC_UP_LIMIT_MS
    }
}
///
/// # Safety
/// Call only for the board NFC IRQ with the NFC chip callbacks installed.
pub unsafe fn nfc_handler() {
    // SAFETY: The NFC chip callbacks are installed; shared chip state is accessed under the NFC I/O lock.
    unsafe {
        with_io(|io, chip, now| {
            if NFC.active {
                io.interrupt(now, chip);
            } else {
                let _ = chip.read(wire::FM_REG_MAIN_IRQ, &mut [0; wire::FM_IRQ_BYTES]);
            }
        });
    }
}
unsafe extern "C" fn timer() {
    // SAFETY: The NFC chip callbacks are installed; shared chip state is accessed under the NFC I/O lock.
    unsafe {
        with_io(|io, chip, now| {
            if NFC.active {
                io.tick(now, chip);
                if io.live() {
                    ck_nfc_io_schedule(Some(timer), wire::WTX_INTERVAL_MS);
                }
            }
        });
    }
}
unsafe fn reset_link<P: Provider>() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(NFC.link)).reset();
        NFC.pending = false;
        NFC.length = 0;
        NFC.sent = 0;
        NFC.more = false;
        NFC.budget = ResponseBudget::new();
        (&mut *core::ptr::addr_of_mut!(NFC.request))
            .reset(&mut Stager::<P>(core::marker::PhantomData));
        ck_core_reset::<P>();
    }
}
/// Boot-only mode latch, before any transport or applet is started.
///
/// # Safety
/// Call during boot, before the GPIO NFC IRQ and transport polling can run.
pub unsafe fn ck_nfc_set_mode(active: u8) {
    // SAFETY: The mode latch is set at boot before enabling controller IRQs.
    unsafe {
        NFC.active = active != 0;
        #[cfg(feature = "ctap")]
        {
            NFC.up_available = NFC.active;
        }
    }
}
/// Main-loop startup only. Quiesce USB before leasing its byte allocation.
///
/// # Safety
/// Use the installed Provider on the serialized main loop during NFC startup.
pub unsafe fn init<P: Provider>() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        deinit();
        let mask = ck_nfc_io_lock();
        ck_nfc_io_schedule(None, 0);
        NFC.active = true;
        let now = ck_nfc_io_now();
        // Drop the previous binding before taking the sole static reference.
        NFC.io = Io::new(now, None);
        NFC.io = Io::new(now, Some(&mut *core::ptr::addr_of_mut!(NFC_FRAME)));
        NFC.generation = 0;
        ck_nfc_io_unlock(mask);
        reset_link::<P>();
        with_io(|io, chip, now| io.poll(now, false, chip));
    }
}
unsafe fn fault() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        with_io(|io, _, _| {
            if io.generation() == NFC.generation {
                io.fault();
            }
        });
    }
}
unsafe fn send(packet: &Packet) {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        with_io(|io, chip, _| {
            if io.generation() == NFC.generation && !io.send(packet, chip) {
                io.fault();
            }
        });
    }
}
unsafe fn execute<P: Provider>(continuation: Option<&[u8]>) {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        let started = with_io(|io, _, now| {
            if io.generation() != NFC.generation || !io.begin_execution(now) {
                return false;
            }
            ck_nfc_io_schedule(Some(timer), wire::WTX_INTERVAL_MS);
            true
        });
        if !started {
            return;
        }
        let buffer = crate::transport::ccid::ck_ccid_response_buffer();
        use canokey_rust_core::runtime::owners::OWNER_NFC;
        let n = if let Some(input) = continuation {
            ck_core_exchange::<P>(
                OWNER_NFC,
                input.as_ptr(),
                input.len(),
                buffer,
                apdu::SHORT_REPLY_BYTES,
            )
        } else {
            let outcome = dispatch::<P>(&mut *core::ptr::addr_of_mut!(NFC.request), buffer);
            (&mut *core::ptr::addr_of_mut!(NFC.budget)).begin(outcome.info.as_ref(), outcome.fido);
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
        NFC.more = (&mut *core::ptr::addr_of_mut!(NFC.budget)).consume(n - 2, *buffer.add(n - 2));
        NFC.length = if NFC.more { n - 2 } else { n };
        NFC.sent = 0;
        NFC.pending = true;
    }
}
unsafe fn next_response<P: Provider>() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        if NFC.sent == NFC.length && NFC.more {
            // The existing engine owns response sources/offsets. This request
            // merely continues its stream; no NFC-specific APDU engine exists.
            let command = (&*core::ptr::addr_of!(NFC.budget)).continuation();
            execute::<P>(Some(&command));
            return;
        }
        send_response(None);
    }
}
unsafe fn send_response(retry: Option<Response>) {
    // SAFETY: Link keeps the committed I-block in the main-loop APDU
    // response window. I/O copies it before the borrowed slice expires.
    unsafe {
        with_io(|io, chip, _| {
            if io.generation() != NFC.generation {
                return;
            }
            let (response, offset) = if let Some(response) = retry {
                (response, NFC.sent - usize::from(response.length))
            } else {
                let link = &mut *core::ptr::addr_of_mut!(NFC.link);
                let Ok(response) =
                    link.response(NFC.length - NFC.sent, NFC.more, io.tx_frame_limit(FSC))
                else {
                    io.fault();
                    return;
                };
                (response, NFC.sent)
            };
            let buffer = crate::transport::ccid::ck_ccid_response_buffer();
            let inf = core::slice::from_raw_parts(buffer.add(offset), usize::from(response.length));
            if !io.send_response(response, inf, chip) {
                io.fault();
            }
        });
    }
}
// Keep frame loan and request staging locals off the applet execution path.
#[inline(never)]
unsafe fn receive<P: Provider>() -> Option<Result<Event, canokey_rust_core::runtime::nfc::Error>> {
    // SAFETY: The main loop owns Link and the APDU buffer. The frame loan
    // removes the only backing reference from Io until we return it.
    unsafe {
        let frame = with_io(|io, _, _| {
            if io.generation() != NFC.generation {
                None
            } else {
                io.take_frame()
            }
        })?;
        let buffer = crate::transport::ccid::ck_ccid_response_buffer();
        let event = (&mut *core::ptr::addr_of_mut!(NFC.link)).receive_with(
            frame.bytes(),
            |offset, bytes| {
                let request = &mut *core::ptr::addr_of_mut!(NFC.request);
                if request.len() != offset {
                    return Err(canokey_rust_core::runtime::nfc::Error::Sequence);
                }
                request.append(
                    bytes,
                    core::slice::from_raw_parts_mut(buffer, apdu::SHORT_FRAME_BYTES),
                    &mut Stager::<P>(core::marker::PhantomData),
                );
                Ok(())
            },
        );
        with_io(|io, _, _| io.return_frame(frame)).then_some(event)
    }
}
///
/// # Safety
/// Run on the serialized main loop with its installed Provider while NFC owns the shared APDU buffer.
pub unsafe fn poll<P: Provider>() {
    // SAFETY: The NFC main loop owns the APDU buffer and link; chip access is serialized by the NFC I/O lock.
    unsafe {
        if !NFC.active {
            return;
        }
        let dirty = (&*core::ptr::addr_of!(NFC.link)).dirty() || NFC.pending;
        let (generation, tx_done) = with_io(|io, chip, now| {
            // Keep UP expired even after the millisecond clock wraps.
            #[cfg(feature = "ctap")]
            if NFC.up_available && now >= NFC_UP_LIMIT_MS {
                NFC.up_available = false;
            }
            io.poll(now, dirty, chip);
            (
                io.generation(),
                io.generation() == NFC.generation && io.take_tx_done(),
            )
        });
        if generation != NFC.generation {
            NFC.generation = generation;
            reset_link::<P>();
            return;
        }
        if tx_done && let Some(n) = (&mut *core::ptr::addr_of_mut!(NFC.link)).sent() {
            NFC.sent += n;
        }
        if NFC.pending {
            match with_io(|io, _, _| io.complete_execution()) {
                None => return,
                Some(false) => {
                    reset_link::<P>();
                    return;
                }
                Some(true) => {
                    NFC.pending = false;
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
            Ok(Event::Send(packet)) => send(&packet),
            Ok(Event::RetryResponse(response)) => {
                send_response(Some(response));
            }
            Ok(Event::NextResponse) => next_response::<P>(),
            Ok(Event::Ignored) => with_io(|io, _, _| io.ignored(NFC.generation)),
            Ok(Event::Deselect) => {
                send(&Packet::deselect());
                reset_link::<P>();
            }
            Ok(Event::Waiting(_)) | Err(_) => fault(),
        }
    }
}

/// Boot-only stored NFC disable policy, before GPIO IRQ is enabled.
///
/// # Safety
/// Call during boot, before the GPIO NFC IRQ and transport polling can run.
pub unsafe fn ck_nfc_silence() -> i32 {
    if Hardware.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_SILENCE]) {
        0
    } else {
        -1
    }
}
