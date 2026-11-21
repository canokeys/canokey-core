// SPDX-License-Identifier: Apache-2.0
//! IRQ-local USB facade. No USB event accesses Core, APDU/HID/CCID parsers or PKE.
//! All exports except init/deinit require the platform IRQ mask. Native packet
//! callbacks publish mailboxes only. No Rust borrow crosses such a callback.
use crate::transport::usb_locked;
#[cfg(test)]
pub(crate) mod tests;
use canokey_protocol::usb::*;
// Two halt bits per endpoint: OUT then IN, including EP0.
const HALT_BITS_PER_ENDPOINT: u8 = 2;
const HALT_PAIR_MASK: u8 = 0x03;
#[inline(always)]
fn halt_bit(ep: u8) -> u8 {
    1 << ((ep & ENDPOINT_NUMBER_MASK) * HALT_BITS_PER_ENDPOINT + (ep >> 7))
}
use canokey_rust_core::runtime::usb::{
    ControlIn, Device, Reply,
    descriptors::{Configuration, Interfaces},
};
const INTERFACES: Interfaces = Interfaces {
    webusb: cfg!(feature = "usb-webusb"),
    hid: cfg!(feature = "usb-hid"),
    keyboard: cfg!(feature = "usb-keyboard"),
};
use crate::sys::ck_usb_dcd_address;
use crate::sys::ck_usb_dcd_close;
use crate::sys::ck_usb_dcd_enable_irq;
use crate::sys::ck_usb_dcd_open;
use crate::sys::ck_usb_dcd_ready;
use crate::sys::ck_usb_dcd_receive;
use crate::sys::ck_usb_dcd_stall;
use crate::sys::ck_usb_dcd_start;
use crate::sys::ck_usb_dcd_stop;
use crate::sys::ck_usb_dcd_write;
use crate::transport::ccid::io::{ck_ccid_io_generation, ck_ccid_packet_out, ck_ccid_packet_reset};
#[cfg(feature = "usb-hid")]
use crate::transport::hid::io::{ck_hid_packet_out, ck_hid_packet_reset};
#[cfg(feature = "usb-keyboard")]
use crate::transport::keyboard::io::ck_keyboard_packet_reset;
#[derive(Clone, Copy)]
struct Tx {
    bytes: *const u8,
    remaining: u16,
    zlp: bool,
    active: bool,
}
impl Tx {
    const EMPTY: Self = Self {
        bytes: core::ptr::null(),
        remaining: 0,
        zlp: false,
        active: false,
    };
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Idle,
    DataIn,
    StatusOut,
    StatusIn,
    Led,
    #[cfg(feature = "usb-webusb")]
    WebReceive,
    #[cfg(feature = "usb-webusb")]
    WebStatus,
}
const CONFIGURATION: Configuration = Configuration::new(INTERFACES);
// Keep byte-sized IRQ flags in reach of Thumb-1 immediate loads.
#[repr(C)]
struct UsbState {
    // IRQ owns protocol and endpoint flags. Main-loop changes use the USB mask.
    device: Device,
    halted: u8,
    suspended: bool,
    // IRQ owns EP0. Locked WebUSB admission and lifecycle callbacks may also
    // advance or reset the active transfer.
    phase: Phase,
    #[cfg(feature = "usb-webusb")]
    control_web: bool,
    control_source: canokey_rust_core::runtime::usb::bos::Descriptor,
    descriptor_active: bool,
    control_in: ControlIn,
    // IRQ and main loop share lifecycle acknowledgement and IN leases under
    // the USB mask.
    lifecycle: canokey_transport_runtime::usb::Lifecycle,
    tx: [Tx; 4],
    control: [u8; CONTROL_BUFFER_BYTES],
}

static mut USB: UsbState = UsbState {
    device: Device::new(),
    halted: 0,
    suspended: false,
    phase: Phase::Idle,
    #[cfg(feature = "usb-webusb")]
    control_web: false,
    control_source: canokey_rust_core::runtime::usb::bos::Descriptor::Bos,
    descriptor_active: false,
    control_in: ControlIn::new(),
    lifecycle: canokey_transport_runtime::usb::Lifecycle::new(),
    tx: [Tx::EMPTY; 4],
    control: [0; CONTROL_BUFFER_BYTES],
};

unsafe fn stall() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        #[cfg(feature = "usb-webusb")]
        if USB.control_web || USB.phase == Phase::WebReceive {
            crate::transport::webusb::reset();
            USB.control_web = false;
        }
        USB.phase = Phase::Idle;
        ck_usb_dcd_stall(0, 1);
        ck_usb_dcd_stall(0x80, 1);
    }
}
unsafe fn status(phase: Phase) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        USB.phase = phase;
        if ck_usb_dcd_write(0x80, core::ptr::null(), 0) == 0 {
            stall();
        }
    }
}
unsafe fn next_control() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if let Some((offset, len)) = (&mut *core::ptr::addr_of_mut!(USB.control_in)).next_packet() {
            let pointer = if USB.descriptor_active {
                let source = USB.control_source;
                source.read(
                    offset,
                    &mut (&mut *core::ptr::addr_of_mut!(USB.control))[..len],
                );
                core::ptr::addr_of!(USB.control).cast::<u8>()
            } else {
                core::ptr::addr_of!(USB.control).cast::<u8>().add(offset)
            };
            #[cfg(feature = "usb-webusb")]
            let pointer = if USB.control_web {
                crate::transport::webusb::pointer(offset)
            } else {
                pointer
            };
            let [lo, hi, ..] = len.to_le_bytes();
            if ck_usb_dcd_write(0x80, pointer, u16::from_le_bytes([lo, hi])) == 0 {
                stall();
            }
        } else {
            #[cfg(feature = "usb-webusb")]
            if USB.control_web {
                crate::transport::webusb::completed();
                USB.control_web = false;
            }
            USB.phase = Phase::StatusOut;
        }
        ck_usb_dcd_receive(0);
    }
}
unsafe fn mailbox_reset(ep: u8) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        USB.tx[ep as usize] = Tx::EMPTY;
        USB.halted &= !(HALT_PAIR_MASK << (ep * HALT_BITS_PER_ENDPOINT));
        match ep {
            EP_CCID => ck_ccid_packet_reset(),
            #[cfg(feature = "usb-hid")]
            EP_HID => ck_hid_packet_reset(),
            #[cfg(feature = "usb-keyboard")]
            EP_KEYBOARD => ck_keyboard_packet_reset(),
            _ => (),
        }
    }
}
unsafe fn reset_pipe(ep: u8, enabled: bool, receive: bool) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        ck_usb_dcd_close(ep);
        ck_usb_dcd_close(ep | DIRECTION_IN);
        mailbox_reset(ep);
        if enabled {
            ck_usb_dcd_open(ep);
            ck_usb_dcd_open(ep | DIRECTION_IN);
            if receive {
                ck_usb_dcd_receive(ep);
            }
        }
    }
}
unsafe fn endpoints(enabled: bool) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        #[cfg(feature = "usb-webusb")]
        crate::transport::webusb::lifecycle_reset();
        USB.device.configured = false;
        for ep in EP_KEYBOARD..=EP_CCID {
            reset_pipe(ep, enabled && INTERFACES.endpoint(ep as u16), false);
        }
        USB.device.configured = enabled;
        ck_usb_dcd_ready(0);
    }
}

unsafe fn ready() -> bool {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        (&*core::ptr::addr_of!(USB.lifecycle)).ready(USB.device.configured, ck_ccid_io_generation())
    }
}

pub(crate) fn service_generation() -> u32 {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe { ck_ccid_io_generation() })
}

/// A reset IRQ during main-loop cleanup invalidates the captured generation.
/// Reopen reception only after all cleanup completed without another reset.
pub(crate) fn service_complete(generation: u32) -> bool {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        let Some(changed) = (&mut *core::ptr::addr_of_mut!(USB.lifecycle))
            .complete(generation, ck_ccid_io_generation())
        else {
            return false;
        };
        if changed {
            if USB.device.configured {
                for ep in EP_KEYBOARD..=EP_CCID {
                    if INTERFACES.endpoint(ep as u16) {
                        ck_usb_dcd_receive(ep);
                    }
                }
                ck_usb_dcd_ready(1);
            }
        }
        true
    })
}

// Invalidate software mailboxes without touching hardware FIFOs on BUSRST.
unsafe fn reset_software_pipes() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        for ep in EP_KEYBOARD..=EP_CCID {
            mailbox_reset(ep);
        }
    }
}
unsafe fn begin_data_in(length: usize, requested: u16, zero_phase: Option<Phase>) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if requested == 0
            && let Some(zero_phase) = zero_phase
        {
            status(zero_phase);
            return;
        }
        start_data_in(length, requested);
    }
}
unsafe fn start_data_in(length: usize, requested: u16) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(USB.control_in)).begin(length, requested);
        USB.phase = Phase::DataIn;
        next_control();
    }
}
///
/// # Safety
/// Call from the serialized main loop with the board USB driver installed and USB startup quiescent.
pub unsafe fn init() {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        ck_usb_dcd_start();
        // USBD_LL_Reset in the C stack only resets protocol state and opens
        // the already-reset EP0. Do not touch FIFO/status registers here;
        // the controller owns the initial control FIFO state.
        ck_usb_boot_reset();
        // Match the C LL startup order: software reset must be complete
        // before USB IRQs can process the first BUSRST/SETUP sequence.
        ck_usb_dcd_enable_irq();
    });
}

pub unsafe fn ck_usb_boot_reset() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        ck_usb_bus_reset();
        // The controller initializes EP0; no SET_ADDRESS or FIFO writes here.
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
    }
}
///
/// # Safety
/// Call on the serialized main loop with the board USB driver installed.
pub unsafe fn deinit() {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        ck_usb_dcd_stop();
        ck_usb_reset();
    });
}
pub unsafe fn ck_usb_reset() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        endpoints(false);
        #[cfg(feature = "usb-webusb")]
        {
            USB.control_web = false;
        }
        USB.suspended = false;
        ck_usb_dcd_close(0);
        ck_usb_dcd_close(0x80);
        (&mut *core::ptr::addr_of_mut!(USB.device)).reset();
        USB.phase = Phase::Idle;
        ck_usb_dcd_address(0);
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
        ck_usb_dcd_receive(0);
    }
}

/// Hardware bus reset is already latched and EP0 remains owned by the USB
/// controller. Match the legacy C LL reset: reset protocol state and disable
/// configured data pipes without closing/reopening EP0 from the IRQ.
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch. The controller must already have processed its hardware bus reset.
pub unsafe fn ck_usb_bus_reset() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        #[cfg(feature = "usb-webusb")]
        {
            crate::transport::webusb::lifecycle_reset();
            USB.control_web = false;
        }
        ck_usb_dcd_ready(0);
        reset_software_pipes();
        USB.suspended = false;
        (&mut *core::ptr::addr_of_mut!(USB.device)).reset();
        USB.phase = Phase::Idle;
        USB.descriptor_active = false;
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
pub unsafe fn ck_usb_suspend() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        USB.suspended = true;
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
pub unsafe fn ck_usb_resume() {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        USB.suspended = false;
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
/// The setup packet memory must be readable for `length` bytes during the call.
pub unsafe fn ck_usb_setup(bytes: *const u8, length: u16) {
    // SAFETY: The IRQ owns the reported RX buffer and masks competing access while it is read.
    unsafe {
        // SETUP supersedes the preceding transfer, including unacknowledged IN.
        ck_usb_dcd_close(0);
        ck_usb_dcd_close(0x80);
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
        #[cfg(feature = "usb-webusb")]
        {
            crate::transport::webusb::abort_control();
            USB.control_web = false;
        }
        USB.phase = Phase::Idle;
        USB.descriptor_active = false;
        if length != 8 {
            stall();
            return;
        }
        let Some(s) = Setup::decode(core::slice::from_raw_parts(bytes, 8)) else {
            stall();
            return;
        };
        #[cfg(feature = "usb-webusb")]
        if USB.device.configured
            && s.index == INTERFACES.webusb() as u16
            && s.kind & !DIRECTION_IN == VENDOR_INTERFACE_OUT
        {
            use crate::transport::webusb::{self as web, Action};
            match web::setup(s, INTERFACES.webusb(), ready()) {
                Some(Action::Receive) => {
                    USB.phase = Phase::WebReceive;
                    ck_usb_dcd_receive(0);
                }
                Some(Action::Send(n)) => {
                    USB.control_web = true;
                    begin_data_in(n, s.length, Some(Phase::WebStatus));
                }
                Some(Action::Status(value)) => {
                    USB.control[0] = value;
                    // This status reply begins DataIn even for a zero request.
                    begin_data_in(1, s.length, None);
                }
                _ => stall(),
            }
            return;
        }
        let halted = if INTERFACES.endpoint(s.index) {
            USB.halted & halt_bit(s.index.to_le_bytes()[0]) != 0
        } else {
            false
        };
        let reply = (&mut *core::ptr::addr_of_mut!(USB.device)).setup(
            &CONFIGURATION,
            s,
            halted,
            &mut *core::ptr::addr_of_mut!(USB.control),
        );
        match reply {
            Reply::Descriptor(source) => {
                if s.length == 0 {
                    status(Phase::StatusIn);
                    return;
                }
                USB.control_source = source;
                USB.descriptor_active = true;
                begin_data_in(source.len(), s.length, Some(Phase::StatusIn));
            }
            Reply::Data(n) => {
                begin_data_in(n, s.length, Some(Phase::StatusIn));
            }
            Reply::Status => status(Phase::StatusIn),
            Reply::Address(address) => {
                // The CIU controller accepts SET_ADDRESS in the same order
                // as the legacy C stack: program it before the EP0 status ZLP.
                (&mut *core::ptr::addr_of_mut!(USB.device)).address = address;
                ck_usb_dcd_address(address);
                status(Phase::StatusIn);
            }
            Reply::Configure(enabled) => {
                endpoints(enabled);
                status(Phase::StatusIn);
            }
            Reply::Interface(index) => {
                #[cfg(feature = "usb-webusb")]
                if index == INTERFACES.webusb() {
                    crate::transport::webusb::reset();
                    status(Phase::StatusIn);
                    return;
                }

                let ep = if index == INTERFACES.ccid() {
                    EP_CCID
                } else if INTERFACES.hid && index == 0 {
                    EP_HID
                } else {
                    EP_KEYBOARD
                };
                reset_pipe(ep, true, ready());
                status(Phase::StatusIn);
            }
            Reply::Halt(ep, halt) => {
                let bit = halt_bit(ep);
                if halt {
                    USB.halted |= bit;
                } else {
                    USB.halted &= !bit;
                }
                ck_usb_dcd_stall(ep, halt as u8);
                status(Phase::StatusIn);
            }
            Reply::ReceiveLed => {
                USB.phase = Phase::Led;
                ck_usb_dcd_receive(0);
            }
            Reply::Stall => stall(),
        }
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
pub unsafe extern "C" fn ck_usb_configured() -> u8 {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe { USB.device.configured as u8 }
}
pub unsafe fn ck_usb_tx_idle(ep: u8) -> u8 {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        u8::from(
            ep & !ENDPOINT_ADDRESS_MASK == 0
                && ep & ENDPOINT_NUMBER_MASK != 0
                && !USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].active,
        )
    }
}
unsafe fn transmit(ep: u8) -> bool {
    // SAFETY: The masked endpoint owns a live IN buffer whose remaining length bounds this pointer advance.
    unsafe {
        let tx = &mut USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize];
        let n = tx
            .remaining
            .min(if ep & ENDPOINT_NUMBER_MASK == EP_KEYBOARD {
                u16::from(KEYBOARD_PACKET_BYTES.to_le_bytes()[0])
            } else {
                u16::from(DATA_PACKET_BYTES.to_le_bytes()[0])
            });
        if ck_usb_dcd_write(ep | DIRECTION_IN, tx.bytes, n) == 0 {
            return false;
        }
        if n != 0 {
            tx.bytes = tx.bytes.add(n as usize);
        }
        tx.remaining -= n;
        true
    }
}
pub unsafe fn ck_usb_submit(ep: u8, bytes: *const u8, length: u16, zlp: u8) -> i32 {
    // SAFETY: The USB mask protects the IN lease, and the caller retains the buffer until completion.
    unsafe {
        if !USB.device.configured
            || ep & DIRECTION_IN == 0
            || ep & ENDPOINT_NUMBER_MASK == 0
            || !INTERFACES.endpoint(ep as u16)
        {
            return -1;
        }
        if !ready()
            || USB.suspended
            || USB.halted & halt_bit(ep | DIRECTION_IN) != 0
            || USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].active
        {
            return 0;
        }
        if length != 0 && bytes.is_null() {
            return -1;
        }
        USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx {
            bytes,
            remaining: length,
            zlp: zlp != 0 && length != 0,
            active: true,
        };
        if !transmit(ep) {
            USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx::EMPTY;
            return -1;
        }
        1
    }
}
pub unsafe fn ck_usb_receive(ep: u8) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if ready() && ep & DIRECTION_IN == 0 && ep != 0 && INTERFACES.endpoint(ep as u16) {
            ck_usb_dcd_receive(ep);
        }
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
/// The endpoint must identify the completed controller transfer.
pub unsafe fn ck_usb_in(ep: u8) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if ep == 0 || ep == 0x80 {
            match USB.phase {
                Phase::DataIn => next_control(),
                Phase::StatusIn => USB.phase = Phase::Idle,
                #[cfg(feature = "usb-webusb")]
                Phase::WebStatus => {
                    crate::transport::webusb::completed();
                    USB.control_web = false;
                    USB.phase = Phase::Idle;
                }

                _ => (),
            }
        } else if ep & !ENDPOINT_ADDRESS_MASK == 0
            && ready()
            && USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].active
        {
            if USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].remaining != 0 {
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else if USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].zlp {
                USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize].zlp = false;
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else {
                USB.tx[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx::EMPTY;
            }
        }
    }
}
///
/// # Safety
/// Call only with the USB interrupt mask held, including from serialized IRQ dispatch.
/// The controller RX buffer must be readable for `length` bytes during the call.
pub unsafe fn ck_usb_out(ep: u8, bytes: *const u8, length: u16) -> u8 {
    // SAFETY: The IRQ owns the reported RX buffer and masks competing access while it is read.
    unsafe {
        if ep == 0 {
            match USB.phase {
                Phase::StatusOut | Phase::DataIn if length == 0 => {
                    ck_usb_dcd_close(0x80);
                    ck_usb_dcd_open(0x80);
                    #[cfg(feature = "usb-webusb")]
                    if USB.control_web {
                        crate::transport::webusb::abort_control();
                        USB.control_web = false;
                    }
                    USB.phase = Phase::Idle;
                }
                #[cfg(feature = "usb-webusb")]
                Phase::WebReceive => {
                    match crate::transport::webusb::receive(bytes, length as usize) {
                        1 => status(Phase::StatusIn),
                        0 => ck_usb_dcd_receive(0),
                        2 => return 0,
                        _ => {
                            crate::transport::webusb::reset();
                            stall();
                        }
                    }
                }
                Phase::Led if length == 2 && *bytes == KEYBOARD_REPORT_ID => {
                    USB.device.policy.leds = *bytes.add(1) & KEYBOARD_LED_MASK;
                    status(Phase::StatusIn);
                }
                _ => stall(),
            }
            return 1;
        }
        if !ready() {
            return 0;
        }
        match ep {
            EP_CCID if usize::from(length) <= DATA_PACKET_BYTES => {
                ck_ccid_packet_out(bytes, length)
            }
            #[cfg(feature = "usb-hid")]
            EP_HID if usize::from(length) == DATA_PACKET_BYTES => ck_hid_packet_out(bytes),
            #[cfg(feature = "usb-keyboard")]
            EP_KEYBOARD
                if usize::from(length) == CONSUMER_REPORT_BYTES && *bytes == KEYBOARD_REPORT_ID =>
            {
                USB.device.policy.leds = *bytes.add(1) & KEYBOARD_LED_MASK;
                1
            }
            _ => 1, // Ignore malformed interrupt reports; never parse stale tail.
        }
    }
}

#[cfg(feature = "usb-webusb")]
pub(crate) unsafe fn web_admission(accepted: bool, complete: bool) {
    // SAFETY: The caller holds the USB interrupt mask while accessing controller and endpoint state.
    unsafe {
        if USB.phase != Phase::WebReceive {
            return;
        }
        if !accepted {
            // Main-loop admission already released the input transfer. Refusal
            // must not schedule a Core reset that revokes a retained APDU grant
            // or interrupts the native HID operation borrowing that context.
            USB.phase = Phase::Idle;
            stall();
        } else if complete {
            status(Phase::StatusIn);
            ck_usb_dcd_receive(0);
        } else {
            ck_usb_dcd_receive(0);
        }
    }
}

/// Cooperative progress dispatch is portable policy. Native code only waits
/// one hardware tick before calling this function; no callback enters Core.
#[cfg(test)]
pub unsafe extern "C" fn ck_transport_progress() -> u8 {
    // SAFETY: The serialized main loop services transport progress without borrowing Core.
    unsafe { progress::<crate::platform::Native>() }
}

///
/// # Safety
/// Call on the serialized main loop with the installed Provider. Core may already be executing.
pub unsafe fn progress<P: crate::composition::Provider>() -> u8 {
    use crate::transport::ccid::io::ck_ccid_progress;
    #[cfg(all(feature = "usb-hid", not(test)))]
    use crate::transport::ccid::presence_progress;
    #[cfg(feature = "usb-hid")]
    #[cfg(not(test))]
    use crate::transport::hid::link::{ck_hid_executing, ck_hid_foreign_progress, ck_hid_progress};
    #[cfg(all(test, feature = "usb-hid"))]
    use tests::{ck_hid_executing, ck_hid_foreign_progress, ck_hid_progress, presence_progress};
    // SAFETY: The serialized main loop services transport progress without borrowing Core.
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return crate::transport::nfc::ck_nfc_progress();
        }
        #[cfg(feature = "usb-hid")]
        {
            if ck_hid_executing() != 0 {
                #[cfg(not(test))]
                presence_progress::<P>();
                #[cfg(test)]
                presence_progress();
                return ck_hid_progress();
            }
            ck_hid_foreign_progress();
        }
        #[cfg(feature = "usb-webusb")]
        if let Some(live) = crate::transport::webusb::progress() {
            return live as u8;
        }
        ck_ccid_progress()
    }
}

/// Main-loop settings notification. Only the IRQ-local descriptor snapshot is
/// changed; an in-flight descriptor keeps its captured immutable variant.
///
/// # Safety
/// Call from the serialized settings path while the board USB driver and lock callbacks are installed.
pub unsafe extern "C" fn ck_usb_set_landing(enabled: u8) {
    // SAFETY: The USB interrupt mask serializes the mailbox access inside this closure.
    usb_locked(|| unsafe {
        (&mut *core::ptr::addr_of_mut!(USB.device))
            .policy
            .set_landing(enabled != 0);
    });
}
