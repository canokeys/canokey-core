// SPDX-License-Identifier: Apache-2.0
//! IRQ-local USB facade. No USB event accesses Core, APDU/HID/CCID parsers or PKE.
//! All exports except init/deinit require the platform IRQ mask. Native packet
//! callbacks publish mailboxes only. No Rust borrow crosses such a callback.
use crate::transport::usb_locked;
use canokey_protocol::usb::*;
// HALTED packs two bits per endpoint: OUT then IN, including EP0.
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
use crate::transport::ccid::io::{ck_ccid_packet_out, ck_ccid_packet_reset};
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
static mut DEVICE: Device = Device::new();
static mut TX: [Tx; 4] = [Tx::EMPTY; 4];
static mut HALTED: u8 = 0;
static mut SUSPENDED: bool = false;
static mut CONTROL: [u8; CONTROL_BUFFER_BYTES] = [0; CONTROL_BUFFER_BYTES];
static mut CONTROL_IN: ControlIn = ControlIn::new();
#[cfg(feature = "usb-webusb")]
static mut CONTROL_WEB: bool = false;
static mut CONTROL_SOURCE: Option<canokey_rust_core::runtime::usb::bos::Descriptor> = None;
static mut PHASE: Phase = Phase::Idle;

unsafe fn stall() {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        if CONTROL_WEB || PHASE == Phase::WebReceive {
            crate::transport::webusb::reset();
            CONTROL_WEB = false;
        }
        PHASE = Phase::Idle;
        ck_usb_dcd_stall(0, 1);
        ck_usb_dcd_stall(0x80, 1);
    }
}
unsafe fn status(phase: Phase) {
    unsafe {
        PHASE = phase;
        if ck_usb_dcd_write(0x80, core::ptr::null(), 0) == 0 {
            stall();
        }
    }
}
unsafe fn next_control() {
    unsafe {
        if let Some((offset, len)) = (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).next_packet() {
            let pointer = if let Some(source) = CONTROL_SOURCE {
                source.read(offset, &mut (&mut *core::ptr::addr_of_mut!(CONTROL))[..len]);
                core::ptr::addr_of!(CONTROL).cast::<u8>()
            } else {
                core::ptr::addr_of!(CONTROL).cast::<u8>().add(offset)
            };
            #[cfg(feature = "usb-webusb")]
            let pointer = if CONTROL_WEB {
                crate::transport::webusb::pointer(offset)
            } else {
                pointer
            };
            if ck_usb_dcd_write(0x80, pointer, len as u16) == 0 {
                stall();
            }
        } else {
            #[cfg(feature = "usb-webusb")]
            if CONTROL_WEB {
                crate::transport::webusb::completed();
                CONTROL_WEB = false;
            }
            PHASE = Phase::StatusOut;
        }
        ck_usb_dcd_receive(0);
    }
}
unsafe fn mailbox_reset(ep: u8) {
    unsafe {
        TX[ep as usize] = Tx::EMPTY;
        HALTED &= !(HALT_PAIR_MASK << (ep * HALT_BITS_PER_ENDPOINT));
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
unsafe fn reset_pipe(ep: u8, enabled: bool) {
    unsafe {
        ck_usb_dcd_close(ep);
        ck_usb_dcd_close(ep | DIRECTION_IN);
        mailbox_reset(ep);
        if enabled {
            ck_usb_dcd_open(ep);
            ck_usb_dcd_open(ep | DIRECTION_IN);
            ck_usb_dcd_receive(ep);
        }
    }
}
unsafe fn endpoints(enabled: bool) {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        crate::transport::webusb::reset();
        DEVICE.configured = false;
        for ep in EP_KEYBOARD..=EP_CCID {
            reset_pipe(ep, enabled && INTERFACES.endpoint(ep as u16));
        }
        DEVICE.configured = enabled;
        ck_usb_dcd_ready(enabled as u8);
    }
}

// Invalidate software mailboxes without touching hardware FIFOs on BUSRST.
unsafe fn reset_software_pipes() {
    unsafe {
        for ep in EP_KEYBOARD..=EP_CCID {
            mailbox_reset(ep);
        }
    }
}
unsafe fn begin_data_in(length: usize, requested: u16, zero_phase: Option<Phase>) {
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
    unsafe {
        (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).begin(length, requested);
        PHASE = Phase::DataIn;
        next_control();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_init() {
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
    unsafe {
        ck_usb_bus_reset();
        // The controller initializes EP0; no SET_ADDRESS or FIFO writes here.
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_deinit() {
    usb_locked(|| unsafe {
        ck_usb_dcd_stop();
        ck_usb_reset();
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_reset() {
    unsafe {
        endpoints(false);
        #[cfg(feature = "usb-webusb")]
        {
            CONTROL_WEB = false;
        }
        SUSPENDED = false;
        ck_usb_dcd_close(0);
        ck_usb_dcd_close(0x80);
        (&mut *core::ptr::addr_of_mut!(DEVICE)).reset();
        PHASE = Phase::Idle;
        ck_usb_dcd_address(0);
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
        ck_usb_dcd_receive(0);
    }
}

/// Hardware bus reset is already latched and EP0 remains owned by the USB
/// controller. Match the legacy C LL reset: reset protocol state and disable
/// configured data pipes without closing/reopening EP0 from the IRQ.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_bus_reset() {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        {
            crate::transport::webusb::reset();
            CONTROL_WEB = false;
        }
        ck_usb_dcd_ready(0);
        reset_software_pipes();
        SUSPENDED = false;
        (&mut *core::ptr::addr_of_mut!(DEVICE)).reset();
        PHASE = Phase::Idle;
        CONTROL_SOURCE = None;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_suspend() {
    unsafe {
        SUSPENDED = true;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_resume() {
    unsafe {
        SUSPENDED = false;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_setup(bytes: *const u8, length: u16) {
    unsafe {
        // SETUP supersedes the preceding transfer, including unacknowledged IN.
        ck_usb_dcd_close(0);
        ck_usb_dcd_close(0x80);
        ck_usb_dcd_open(0);
        ck_usb_dcd_open(0x80);
        #[cfg(feature = "usb-webusb")]
        {
            crate::transport::webusb::abort_control();
            CONTROL_WEB = false;
        }
        PHASE = Phase::Idle;
        CONTROL_SOURCE = None;
        if length != 8 {
            stall();
            return;
        }
        let Some(s) = Setup::decode(core::slice::from_raw_parts(bytes, 8)) else {
            stall();
            return;
        };
        #[cfg(feature = "usb-webusb")]
        if DEVICE.configured
            && s.index == INTERFACES.webusb() as u16
            && s.kind & !DIRECTION_IN == VENDOR_INTERFACE_OUT
        {
            use crate::transport::webusb::{self as web, Action};
            match web::setup(s, INTERFACES.webusb()) {
                Some(Action::Receive) => {
                    PHASE = Phase::WebReceive;
                    ck_usb_dcd_receive(0);
                }
                Some(Action::Send(n)) => {
                    CONTROL_WEB = true;
                    begin_data_in(n, s.length, Some(Phase::WebStatus));
                }
                Some(Action::Status(value)) => {
                    CONTROL[0] = value;
                    // This status reply begins DataIn even for a zero request.
                    begin_data_in(1, s.length, None);
                }
                _ => stall(),
            }
            return;
        }
        let halted = if INTERFACES.endpoint(s.index) {
            HALTED & halt_bit(s.index as u8) != 0
        } else {
            false
        };
        let reply = (&mut *core::ptr::addr_of_mut!(DEVICE)).setup(
            &CONFIGURATION,
            s,
            halted,
            &mut *core::ptr::addr_of_mut!(CONTROL),
        );
        match reply {
            Reply::Descriptor(source) => {
                if s.length == 0 {
                    status(Phase::StatusIn);
                    return;
                }
                CONTROL_SOURCE = Some(source);
                begin_data_in(source.len(), s.length, Some(Phase::StatusIn));
            }
            Reply::Data(n) => {
                begin_data_in(n, s.length, Some(Phase::StatusIn));
            }
            Reply::Status => status(Phase::StatusIn),
            Reply::Address(address) => {
                // The CIU controller accepts SET_ADDRESS in the same order
                // as the legacy C stack: program it before the EP0 status ZLP.
                (&mut *core::ptr::addr_of_mut!(DEVICE)).address = address;
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
                reset_pipe(ep, true);
                status(Phase::StatusIn);
            }
            Reply::Halt(ep, halt) => {
                let bit = halt_bit(ep);
                if halt {
                    HALTED |= bit;
                } else {
                    HALTED &= !bit;
                }
                ck_usb_dcd_stall(ep, halt as u8);
                status(Phase::StatusIn);
            }
            Reply::ReceiveLed => {
                PHASE = Phase::Led;
                ck_usb_dcd_receive(0);
            }
            Reply::Stall => stall(),
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_configured() -> u8 {
    unsafe { DEVICE.configured as u8 }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_tx_idle(ep: u8) -> u8 {
    unsafe {
        u8::from(
            ep & !ENDPOINT_ADDRESS_MASK == 0
                && ep & ENDPOINT_NUMBER_MASK != 0
                && !TX[(ep & ENDPOINT_NUMBER_MASK) as usize].active,
        )
    }
}
unsafe fn transmit(ep: u8) -> bool {
    unsafe {
        let tx = &mut TX[(ep & ENDPOINT_NUMBER_MASK) as usize];
        let n = tx
            .remaining
            .min(if ep & ENDPOINT_NUMBER_MASK == EP_KEYBOARD {
                KEYBOARD_PACKET_BYTES as u16
            } else {
                DATA_PACKET_BYTES as u16
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_submit(ep: u8, bytes: *const u8, length: u16, zlp: u8) -> i32 {
    unsafe {
        if !DEVICE.configured
            || ep & DIRECTION_IN == 0
            || ep & ENDPOINT_NUMBER_MASK == 0
            || !INTERFACES.endpoint(ep as u16)
        {
            return -1;
        }
        if SUSPENDED
            || HALTED & halt_bit(ep | DIRECTION_IN) != 0
            || TX[(ep & ENDPOINT_NUMBER_MASK) as usize].active
        {
            return 0;
        }
        if length != 0 && bytes.is_null() {
            return -1;
        }
        TX[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx {
            bytes,
            remaining: length,
            zlp: zlp != 0 && length != 0,
            active: true,
        };
        if !transmit(ep) {
            TX[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx::EMPTY;
            return -1;
        }
        1
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_receive(ep: u8) {
    unsafe {
        if DEVICE.configured && ep & DIRECTION_IN == 0 && ep != 0 && INTERFACES.endpoint(ep as u16)
        {
            ck_usb_dcd_receive(ep);
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_in(ep: u8) {
    unsafe {
        if ep == 0 || ep == 0x80 {
            match PHASE {
                Phase::DataIn => next_control(),
                Phase::StatusIn => PHASE = Phase::Idle,
                #[cfg(feature = "usb-webusb")]
                Phase::WebStatus => {
                    crate::transport::webusb::completed();
                    CONTROL_WEB = false;
                    PHASE = Phase::Idle;
                }

                _ => (),
            }
        } else if ep & !ENDPOINT_ADDRESS_MASK == 0
            && DEVICE.configured
            && TX[(ep & ENDPOINT_NUMBER_MASK) as usize].active
        {
            if TX[(ep & ENDPOINT_NUMBER_MASK) as usize].remaining != 0 {
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else if TX[(ep & ENDPOINT_NUMBER_MASK) as usize].zlp {
                TX[(ep & ENDPOINT_NUMBER_MASK) as usize].zlp = false;
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else {
                TX[(ep & ENDPOINT_NUMBER_MASK) as usize] = Tx::EMPTY;
            }
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_out(ep: u8, bytes: *const u8, length: u16) -> u8 {
    unsafe {
        if ep == 0 {
            match PHASE {
                Phase::StatusOut | Phase::DataIn if length == 0 => {
                    ck_usb_dcd_close(0x80);
                    ck_usb_dcd_open(0x80);
                    #[cfg(feature = "usb-webusb")]
                    if CONTROL_WEB {
                        crate::transport::webusb::abort_control();
                        CONTROL_WEB = false;
                    }
                    PHASE = Phase::Idle;
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
                    DEVICE.leds = *bytes.add(1) & KEYBOARD_LED_MASK;
                    status(Phase::StatusIn);
                }
                _ => stall(),
            }
            return 1;
        }
        if !DEVICE.configured {
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
                DEVICE.leds = *bytes.add(1) & KEYBOARD_LED_MASK;
                1
            }
            _ => 1, // Ignore malformed interrupt reports; never parse stale tail.
        }
    }
}

#[cfg(feature = "usb-webusb")]
pub(crate) unsafe fn web_admission(accepted: bool, complete: bool) {
    unsafe {
        if PHASE != Phase::WebReceive {
            return;
        }
        if !accepted {
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_transport_progress() -> u8 {
    use crate::transport::ccid::io::ck_ccid_progress;
    #[cfg(feature = "usb-hid")]
    use crate::transport::hid::link::{ck_hid_executing, ck_hid_foreign_progress, ck_hid_progress};
    unsafe {
        #[cfg(feature = "nfc")]
        if crate::transport::nfc::is_nfc() != 0 {
            return crate::transport::nfc::ck_nfc_progress();
        }
        #[cfg(feature = "usb-hid")]
        {
            if ck_hid_executing() != 0 {
                crate::transport::ccid::presence_progress();
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_set_landing(enabled: u8) {
    usb_locked(|| unsafe {
        DEVICE.landing = enabled != 0;
    });
}
