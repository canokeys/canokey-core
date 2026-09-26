// SPDX-License-Identifier: Apache-2.0
//! IRQ-local USB facade. No USB event accesses Core, APDU/HID/CCID parsers or PKE.
//! All exports except init/deinit require the platform IRQ mask. Native packet
//! callbacks publish mailboxes only. No Rust borrow crosses such a callback.
use canokey_protocol::usb::Setup;
use canokey_rust_core::runtime::usb::{ControlIn, Device, Reply, descriptors::Interfaces};
const INTERFACES: Interfaces = Interfaces {
    webusb: cfg!(feature = "usb-webusb"),
    hid: cfg!(feature = "usb-hid"),
    keyboard: cfg!(feature = "usb-keyboard"),
};
unsafe extern "C" {
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
    fn ck_usb_dcd_start();
    fn ck_usb_dcd_stop();
    fn ck_usb_dcd_open(ep: u8);
    fn ck_usb_dcd_close(ep: u8);
    fn ck_usb_dcd_stall(ep: u8, halt: u8);
    fn ck_usb_dcd_address(address: u8);
    fn ck_usb_dcd_receive(ep: u8);
    fn ck_usb_dcd_write(ep: u8, bytes: *const u8, length: u16) -> u8;
    fn ck_usb_dcd_ready(ready: u8);
    fn ck_ccid_packet_reset();
    fn ck_ccid_packet_out(bytes: *const u8, length: u16) -> u8;
    #[cfg(feature = "usb-hid")]
    fn ck_hid_packet_reset();
    #[cfg(feature = "usb-hid")]
    fn ck_hid_packet_out(bytes: *const u8) -> u8;
    #[cfg(feature = "usb-keyboard")]
    fn ck_keyboard_packet_reset();
}
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
    Address(u8),
    Led,
    #[cfg(feature = "usb-webusb")]
    WebReceive,
    #[cfg(feature = "usb-webusb")]
    WebStatus,
}
static mut DEVICE: Device = Device::new(INTERFACES);
static mut TX: [Tx; 4] = [Tx::EMPTY; 4];
static mut HALTED: u8 = 0;
static mut SUSPENDED: bool = false;
static mut CONTROL: [u8; 160] = [0; 160];
static mut CONTROL_IN: ControlIn = ControlIn::new();
#[cfg(feature = "usb-webusb")]
static mut CONTROL_WEB: bool = false;
static mut CONTROL_SOURCE: Option<canokey_rust_core::runtime::usb::webusb::Descriptor> = None;
static mut PHASE: Phase = Phase::Idle;

unsafe fn stall() {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        if CONTROL_WEB || PHASE == Phase::WebReceive {
            super::webusb_link::reset();
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
                super::webusb_link::pointer(offset)
            } else {
                pointer
            };
            if ck_usb_dcd_write(0x80, pointer, len as u16) == 0 {
                stall();
            }
        } else {
            #[cfg(feature = "usb-webusb")]
            if CONTROL_WEB {
                super::webusb_link::completed();
                CONTROL_WEB = false;
            }
            PHASE = Phase::StatusOut;
        }
        ck_usb_dcd_receive(0);
    }
}
unsafe fn reset_pipe(ep: u8, enabled: bool) {
    unsafe {
        ck_usb_dcd_close(ep);
        ck_usb_dcd_close(ep | 0x80);
        TX[ep as usize] = Tx::EMPTY;
        HALTED &= !(3 << (ep * 2));
        match ep {
            3 => ck_ccid_packet_reset(),
            #[cfg(feature = "usb-hid")]
            2 => ck_hid_packet_reset(),
            #[cfg(feature = "usb-keyboard")]
            1 => ck_keyboard_packet_reset(),
            _ => (),
        }
        if enabled {
            ck_usb_dcd_open(ep);
            ck_usb_dcd_open(ep | 0x80);
            ck_usb_dcd_receive(ep);
        }
    }
}
unsafe fn endpoints(enabled: bool) {
    unsafe {
        #[cfg(feature = "usb-webusb")]
        super::webusb_link::reset();
        DEVICE.configured = false;
        for ep in 1..=3 {
            reset_pipe(ep, enabled && INTERFACES.endpoint(ep as u16));
        }
        DEVICE.configured = enabled;
        ck_usb_dcd_ready(enabled as u8);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_init() {
    unsafe {
        let mask = ck_usb_dcd_lock();
        ck_usb_dcd_start();
        ck_usb_reset();
        ck_usb_dcd_unlock(mask);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usb_device_deinit() {
    unsafe {
        let mask = ck_usb_dcd_lock();
        ck_usb_dcd_stop();
        ck_usb_reset();
        ck_usb_dcd_unlock(mask);
    }
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
        ck_usb_dcd_stall(0, 0);
        ck_usb_dcd_stall(0x80, 0);
        #[cfg(feature = "usb-webusb")]
        {
            super::webusb_link::abort_control();
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
        if DEVICE.configured && s.index == INTERFACES.webusb() as u16 && s.kind & 0x7f == 0x41 {
            use super::webusb_link::{self as web, Action};
            match web::setup(s, INTERFACES.webusb()) {
                Some(Action::Receive) => {
                    PHASE = Phase::WebReceive;
                    ck_usb_dcd_receive(0);
                }
                Some(Action::Send(n)) => {
                    CONTROL_WEB = true;
                    if s.length == 0 {
                        status(Phase::WebStatus);
                    } else {
                        (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).begin(n, s.length);
                        PHASE = Phase::DataIn;
                        next_control();
                    }
                }
                Some(Action::Status(value)) => {
                    CONTROL[0] = value;
                    (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).begin(1, s.length);
                    PHASE = Phase::DataIn;
                    next_control();
                }
                _ => stall(),
            }
            return;
        }
        let halted = if INTERFACES.endpoint(s.index) {
            HALTED & (1 << ((s.index as u8 & 3) * 2 + ((s.index >> 7) as u8))) != 0
        } else {
            false
        };
        let reply = (&mut *core::ptr::addr_of_mut!(DEVICE)).setup(
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
                (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).begin(source.len(), s.length);
                PHASE = Phase::DataIn;
                next_control();
            }
            Reply::Data(n) => {
                if s.length == 0 {
                    status(Phase::StatusIn);
                } else {
                    (&mut *core::ptr::addr_of_mut!(CONTROL_IN)).begin(n, s.length);
                    PHASE = Phase::DataIn;
                    next_control();
                }
            }
            Reply::Status => status(Phase::StatusIn),
            Reply::Address(address) => status(Phase::Address(address)),
            Reply::Configure(enabled) => {
                endpoints(enabled);
                status(Phase::StatusIn);
            }
            Reply::Interface(index) => {
                #[cfg(feature = "usb-webusb")]
                if index == INTERFACES.webusb() {
                    super::webusb_link::reset();
                    status(Phase::StatusIn);
                    return;
                }

                let ep = if index == INTERFACES.ccid() {
                    3
                } else if INTERFACES.hid && index == 0 {
                    2
                } else {
                    1
                };
                reset_pipe(ep, true);
                status(Phase::StatusIn);
            }
            Reply::Halt(ep, halt) => {
                let bit = 1 << ((ep & 3) * 2 + (ep >> 7));
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
    unsafe { u8::from(ep & !0x83 == 0 && ep & 3 != 0 && !TX[(ep & 3) as usize].active) }
}
unsafe fn transmit(ep: u8) -> bool {
    unsafe {
        let tx = &mut TX[(ep & 3) as usize];
        let n = tx.remaining.min(if ep & 3 == 1 { 8 } else { 64 });
        if ck_usb_dcd_write(ep | 0x80, tx.bytes, n) == 0 {
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
        if !DEVICE.configured || ep & 0x80 == 0 || ep & 0x7f == 0 || !INTERFACES.endpoint(ep as u16)
        {
            return -1;
        }
        if SUSPENDED || HALTED & (1 << ((ep & 3) * 2 + 1)) != 0 || TX[(ep & 3) as usize].active {
            return 0;
        }
        if length != 0 && bytes.is_null() {
            return -1;
        }
        TX[(ep & 3) as usize] = Tx {
            bytes,
            remaining: length,
            zlp: zlp != 0 && length != 0,
            active: true,
        };
        if !transmit(ep) {
            TX[(ep & 3) as usize] = Tx::EMPTY;
            return -1;
        }
        1
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_receive(ep: u8) {
    unsafe {
        if DEVICE.configured && ep & 0x80 == 0 && ep != 0 && INTERFACES.endpoint(ep as u16) {
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
                Phase::Address(address) => {
                    DEVICE.address = address;
                    PHASE = Phase::Idle;
                    ck_usb_dcd_address(address);
                }
                Phase::StatusIn => PHASE = Phase::Idle,
                #[cfg(feature = "usb-webusb")]
                Phase::WebStatus => {
                    super::webusb_link::completed();
                    CONTROL_WEB = false;
                    PHASE = Phase::Idle;
                }

                _ => (),
            }
        } else if ep & !0x83 == 0 && DEVICE.configured && TX[(ep & 3) as usize].active {
            if TX[(ep & 3) as usize].remaining != 0 {
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else if TX[(ep & 3) as usize].zlp {
                TX[(ep & 3) as usize].zlp = false;
                if !transmit(ep) {
                    ck_usb_reset();
                }
            } else {
                TX[(ep & 3) as usize] = Tx::EMPTY;
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
                        super::webusb_link::abort_control();
                        CONTROL_WEB = false;
                    }
                    PHASE = Phase::Idle;
                }
                #[cfg(feature = "usb-webusb")]
                Phase::WebReceive => match super::webusb_link::receive(bytes, length as usize) {
                    1 => status(Phase::StatusIn),
                    0 => ck_usb_dcd_receive(0),
                    2 => return 0,
                    _ => {
                        super::webusb_link::reset();
                        stall();
                    }
                },
                Phase::Led if length == 2 && *bytes == 1 => {
                    DEVICE.leds = *bytes.add(1) & 31;
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
            3 if length <= 64 => ck_ccid_packet_out(bytes, length),
            #[cfg(feature = "usb-hid")]
            2 if length == 64 => ck_hid_packet_out(bytes),
            #[cfg(feature = "usb-keyboard")]
            1 if length == 2 && *bytes == 1 => {
                DEVICE.leds = *bytes.add(1) & 31;
                1
            }
            _ => 1, // Ignore malformed interrupt reports; never parse stale tail.
        }
    }
}

#[cfg(feature = "usb-webusb")]
pub(super) unsafe fn web_admission(accepted: bool, complete: bool) {
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
    unsafe extern "C" {
        fn ck_ccid_progress() -> u8;
        #[cfg(feature = "usb-hid")]
        fn ck_hid_executing() -> u8;
        #[cfg(feature = "usb-hid")]
        fn ck_hid_progress() -> u8;
    }
    unsafe {
        #[cfg(feature = "nfc")]
        if super::nfc::is_nfc() != 0 {
            return super::nfc::ck_nfc_progress();
        }
        #[cfg(feature = "usb-webusb")]
        if let Some(live) = super::webusb_link::progress() {
            return live as u8;
        }
        #[cfg(feature = "usb-hid")]
        if ck_hid_executing() != 0 {
            return ck_hid_progress();
        }
        ck_ccid_progress()
    }
}

/// Main-loop settings notification. Only the IRQ-local descriptor snapshot is
/// changed; an in-flight descriptor keeps its captured immutable variant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_usb_set_landing(enabled: u8) {
    unsafe {
        let mask = ck_usb_dcd_lock();
        DEVICE.landing = enabled != 0;
        ck_usb_dcd_unlock(mask);
    }
}
