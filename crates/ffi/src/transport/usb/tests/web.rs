// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::transport::webusb::{block_competitor, try_preempt};
use canokey_rust_core::runtime::webusb::{
    RESPONSE_LIMIT, STATUS_HOLD, STATUS_IDLE, STATUS_PROCESSING,
};

struct Policy {
    ccid_idle: bool,
    hid_busy: bool,
    reset_during_exchange: bool,
    exchange_error: bool,
    resets: usize,
    exchanges: usize,
    preemptable: bool,
}
static mut POLICY: Policy = Policy {
    ccid_idle: true,
    hid_busy: false,
    reset_during_exchange: false,
    exchange_error: false,
    resets: 0,
    exchanges: 0,
    preemptable: false,
};
fn policy() -> &'static mut Policy {
    unsafe { &mut *core::ptr::addr_of_mut!(POLICY) }
}
pub(crate) unsafe fn ck_ccid_idle() -> u8 {
    u8::from(policy().ccid_idle)
}
#[cfg(feature = "usb-hid")]
pub(crate) unsafe fn ck_hid_busy() -> u8 {
    u8::from(policy().hid_busy)
}
pub(crate) unsafe fn can_preempt() -> bool {
    policy().preemptable
}
pub(crate) unsafe fn ck_core_reset() {
    policy().resets += 1;
}
pub(crate) unsafe fn ck_core_exchange(
    owner: u8,
    input: *const u8,
    length: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    assert_eq!(owner, crate::transport::owners::OWNER_WEBUSB);
    assert_eq!(input, out.cast_const());
    assert_eq!(capacity, RESPONSE_LIMIT);
    assert!(matches!(length, 5 | 261));
    let input = unsafe { core::slice::from_raw_parts(input, length) };
    if length == SELECT.len() {
        assert_eq!(input, &SELECT);
    } else {
        for (i, byte) in input.iter().enumerate() {
            assert_eq!(*byte, i as u8);
        }
    }
    policy().exchanges += 1;
    // EP0 status/progress while execution owns shared storage must leave it intact.
    let mut bytes = [0; 256];
    setup(VENDOR_INTERFACE_IN, 2, 0, u16::from(INTERFACES.hid), 1);
    assert_eq!(read_control(&mut bytes), 1);
    assert_eq!(bytes[0], STATUS_PROCESSING);
    #[cfg(feature = "usb-hid")]
    let before = controller().foreign_progress;
    assert_eq!(unsafe { ck_transport_progress() }, 1);
    #[cfg(feature = "usb-hid")]
    assert_eq!(controller().foreign_progress, before + 1);
    if policy().reset_during_exchange {
        unsafe { ck_usb_reset() };
        assert_eq!(unsafe { ck_transport_progress() }, 0);
    }
    if policy().exchange_error {
        return -1;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(out, capacity) };
    for (i, byte) in out[..256].iter_mut().enumerate() {
        *byte = i as u8;
    }
    out[256..258].copy_from_slice(&[0x90, 0]);
    RESPONSE_LIMIT as i32
}

pub(super) fn scenario() {
    unsafe {
        let mut bytes = [0; 256];
        let interface = u16::from(INTERFACES.hid);
        // BOS, WebUSB URL index 1 and Microsoft OS 2.0 descriptor set.
        setup(DEVICE_IN, GET_DESCRIPTOR, 0x0f00, 0, 255);
        assert_eq!(read_control(&mut bytes), 57);
        assert_eq!(bytes[1], 15);
        setup(0xc0, 1, 1, 2, 255);
        assert_eq!(read_control(&mut bytes), 23);
        assert_eq!(&bytes[3..23], b"console.canokeys.org");
        setup(0xc0, 2, 0, 7, 255);
        assert_eq!(read_control(&mut bytes), 178);
        assert_eq!(u16::from(bytes[22]), interface);
        let epoch = ck_ccid_io_generation();
        setup(INTERFACE_OUT, SET_INTERFACE, 0, interface, 0);
        status();
        assert_eq!(ck_ccid_io_generation(), epoch);
        crate::transport::webusb::poll::<crate::platform::Native>();
        for hid_busy in [false, true] {
            policy().ccid_idle = hid_busy;
            policy().hid_busy = hid_busy;
            if hid_busy && !INTERFACES.hid {
                continue;
            }
            let before = policy().resets;
            setup(VENDOR_INTERFACE_OUT, 0, 0, interface, SELECT.len() as u16);
            assert_eq!(ck_usb_out(0, SELECT.as_ptr(), SELECT.len() as u16), 0);
            assert!(block_competitor());
            crate::transport::webusb::poll::<crate::platform::Native>();
            assert!(!block_competitor());
            assert!(controller().halted[1]);
            assert_eq!(policy().resets, before);
            assert_eq!(policy().exchanges, 0);
        }
        policy().ccid_idle = true;
        policy().hid_busy = false;
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, SELECT.len() as u16);
        assert_eq!(ck_usb_out(0, SELECT.as_ptr(), SELECT.len() as u16), 0);
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 1);
        setup(VENDOR_INTERFACE_IN, 2, 0, interface, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], 0);
        setup(VENDOR_INTERFACE_IN, 1, 0, interface, 256);
        assert_eq!(read_control(&mut bytes), 256);
        for (i, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, i as u8);
        }
        setup(VENDOR_INTERFACE_IN, 2, 0, interface, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], STATUS_HOLD);
        let before = policy().resets;
        assert!(!try_preempt::<crate::platform::Native>(true));
        policy().preemptable = true;
        assert!(!try_preempt::<crate::platform::Native>(false));
        assert_eq!(policy().resets, before);
        assert!(try_preempt::<crate::platform::Native>(true));
        assert_eq!(policy().resets, before + 1);
        assert!(!block_competitor());
        controller().now += 2000;
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().resets, before + 1);
        policy().preemptable = false;
        setup(VENDOR_INTERFACE_IN, 2, 0, interface, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], STATUS_IDLE);
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, 261);
        let mut fragment: [u8; EP0_PACKET_BYTES] = core::array::from_fn(|i| i as u8);
        assert_eq!(ck_usb_out(0, fragment.as_ptr(), fragment.len() as u16), 0);
        crate::transport::webusb::poll::<crate::platform::Native>();
        for offset in (EP0_PACKET_BYTES..261).step_by(EP0_PACKET_BYTES) {
            let count = (261 - offset).min(EP0_PACKET_BYTES);
            for (i, byte) in fragment.iter_mut().enumerate() {
                *byte = (offset + i) as u8;
            }
            assert_eq!(ck_usb_out(0, fragment.as_ptr(), count as u16), 1);
        }
        status();
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 2);
        setup(VENDOR_INTERFACE_IN, 1, 0, interface, 2);
        assert_eq!(read_control(&mut bytes), 2);
        assert_eq!(&bytes[..2], &[0, 1]);
        controller().now += 2000;
        crate::transport::webusb::poll::<crate::platform::Native>();
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, 0);
        setup(VENDOR_INTERFACE_IN, 2, 0, interface, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], STATUS_IDLE);
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 2);
        policy().exchange_error = true;
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, SELECT.len() as u16);
        assert_eq!(ck_usb_out(0, SELECT.as_ptr(), SELECT.len() as u16), 0);
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 3);
        setup(VENDOR_INTERFACE_IN, 1, 0, interface, RESPONSE_LIMIT as u16);
        assert_eq!(read_control(&mut bytes), 2);
        assert_eq!(&bytes[..2], &[0x6f, 0]);
        controller().now += 2000;
        crate::transport::webusb::poll::<crate::platform::Native>();
        policy().exchange_error = false;
        policy().reset_during_exchange = true;
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, SELECT.len() as u16);
        assert_eq!(ck_usb_out(0, SELECT.as_ptr(), SELECT.len() as u16), 0);
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 4);
        assert!(!controller().ready);
        crate::transport::webusb::poll::<crate::platform::Native>();
        policy().reset_during_exchange = false;
        configure();
        crate::transport::webusb::poll::<crate::platform::Native>();
        setup(VENDOR_INTERFACE_OUT, 0, 0, interface, SELECT.len() as u16);
        assert_eq!(ck_usb_out(0, SELECT.as_ptr(), SELECT.len() as u16), 0);
        bus_reset();
        assert!(!controller().ready);
        assert_eq!(ck_usb_configured(), 0);
        crate::transport::webusb::poll::<crate::platform::Native>();
        assert_eq!(policy().exchanges, 4);
        assert!(!block_competitor());
        setup(DEVICE_OUT, SET_ADDRESS, u16::from(ADDRESS), 0, 0);
        status();
        setup(DEVICE_OUT, SET_CONFIGURATION, 1, 0, 0);
        status();
        setup(VENDOR_INTERFACE_IN, 2, 0, interface, 1);
        assert_eq!(read_control(&mut bytes), 1);
        assert_eq!(bytes[0], STATUS_IDLE);
    }
}
