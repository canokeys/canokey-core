// SPDX-License-Identifier: Apache-2.0
//! Reset IRQs inside real Core erasure, without reentering the active Core borrow.
use super::*;
use canokey_ports::{BackendTypes, Memory, MemoryBackend, Platform};
use canokey_rust_core::runtime::webusb as web_wire;
use canokey_rust_ffi::composition::Provider;
use std::cell::Cell;

const ADDRESS: u16 = 17;
// This fixture installs HID before WebUSB, whose interface number is therefore1.
const WEBUSB_INTERFACE: u16 = 1;

thread_local! {
    static WIPES: Cell<usize> = const { Cell::new(0) };
    static INTERRUPT_AT: Cell<Option<usize>> = const { Cell::new(None) };
    static BUS_RESET: Cell<bool> = const { Cell::new(false) };
    static FIRED: Cell<bool> = const { Cell::new(false) };
}

// This Provider is installed once for the entire process. Its capabilities and
// staging backend are the ordinary fixture's; only erasure adds an IRQ hook.
pub(super) struct Fake;
pub struct InterruptibleMemory;
impl Provider for Fake {
    type Backends = BackendTypes<
        canokey_test_card::storage::Records,
        canokey_native_crypto::CryptoBackend,
        transport::Clock,
        InterruptibleMemory,
    >;
    type Staging = transport::Scratch;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T {
        transport::Fake::with_platform(|p| {
            run(&mut Platform::new(
                p.storage,
                p.crypto,
                p.device,
                &InterruptibleMemory,
            ))
        })
    }
}
impl Memory for InterruptibleMemory {
    fn wipe(&self, bytes: &mut [u8]) {
        MemoryBackend.wipe(bytes);
        WIPES.set(WIPES.get() + 1);
        if INTERRUPT_AT.get() == Some(WIPES.get()) {
            INTERRUPT_AT.set(None);
            FIRED.set(true);
            interrupt();
        }
    }
}

fn reconfigure(reset: bool) {
    if reset {
        hw(|h| {
            h.address = 0;
            h.pending.fill(false);
            h.halted.fill(false);
            h.opened.fill(false);
            h.opened[0] = true;
            h.opened[1] = true;
        });
        unsafe { usb::bus_reset() };
        setup(usb_wire::DEVICE_OUT, usb_wire::SET_ADDRESS, ADDRESS, 0, 0);
        status();
    } else {
        setup(usb_wire::DEVICE_OUT, usb_wire::SET_CONFIGURATION, 0, 0, 0);
        status();
    }
    setup(usb_wire::DEVICE_OUT, usb_wire::SET_CONFIGURATION, 1, 0, 0);
    status();
    assert!(!hw(|h| h.ready));
}

fn interrupt() {
    assert_eq!(hw(|h| h.masked), 0);
    // The platform's USB ISR masks IRQs before entering these raw callbacks.
    hw(|h| h.masked = 1);
    let receives = hw(|h| h.receives);
    reconfigure(BUS_RESET.get());
    // Valid class traffic must not enter the new generation before its own
    // cleanup. Only IRQ entrypoints run here, never a Provider/Core operation.
    let request = ccid_request(ccid_wire::TRANSFER, SELECT_ADMIN, next_sequence());
    assert_eq!(out(usb_wire::EP_CCID, &request), 0);
    let mut init = hid_packet(hid_wire::BROADCAST, hid_wire::INIT, NONCE.len());
    init[hid_wire::INITIAL_HEADER_BYTES..hid_wire::INITIAL_HEADER_BYTES + NONCE.len()]
        .copy_from_slice(NONCE);
    assert_eq!(out(usb_wire::EP_HID, &init), 0);
    setup(
        usb_wire::VENDOR_INTERFACE_IN,
        web_wire::REQUEST_RESPONSE,
        0,
        WEBUSB_INTERFACE,
        web_wire::RESPONSE_LIMIT as u16,
    );
    assert!(hw(|h| h.halted[0] && h.halted[1]));
    setup(
        usb_wire::VENDOR_INTERFACE_OUT,
        web_wire::REQUEST_COMMAND,
        0,
        WEBUSB_INTERFACE,
        SELECT_ADMIN.len() as u16,
    );
    assert!(hw(|h| h.halted[0] && h.halted[1]));
    // EP0 enumeration stays usable even while the old cleanup is on stack.
    setup(usb_wire::DEVICE_IN, usb_wire::GET_CONFIGURATION, 0, 0, 1);
    assert_eq!(read_control(), [1]);
    assert_eq!(hw(|h| h.receives)[1..], receives[1..]);
    hw(|h| h.masked = 0);
}

#[derive(Clone, Copy, Debug)]
enum Retained {
    Pin,
    Response,
    Staged,
}
fn prepare(retained: Retained) {
    reconfigure(false);
    unsafe { usb::service::<Fake>() };
    match retained {
        Retained::Pin => {
            web_apdu(SELECT_ADMIN, 0x9000);
            web_apdu(VERIFY, 0x9000);
        }
        Retained::Response => {
            web_apdu(SELECT_FIDO, 0x9000);
            web_apdu(INFO_SHORT, 0x61ff);
        }
        Retained::Staged => {
            hid_send(hid_wire::BROADCAST, hid_wire::INIT, NONCE);
            let init = hid_read(hid_wire::BROADCAST, hid_wire::INIT);
            let cid = u32::from_be_bytes(init[8..12].try_into().unwrap());
            let mut first = hid_packet(cid, hid_wire::CBOR, 300);
            first[hid_wire::INITIAL_HEADER_BYTES] = 6;
            assert_eq!(out(usb_wire::EP_HID, &first), 0);
            hid_poll();
            assert_ne!(transport::scratch(|s| s.owner), 0);
        }
    }
    reconfigure(false);
}

pub(super) fn run() {
    let mut cases = 0;
    for retained in [Retained::Pin, Retained::Response, Retained::Staged] {
        hw(|h| h.masked = 1);
        prepare(retained);
        WIPES.set(0);
        hw(|h| h.masked = 0);
        unsafe { usb::service::<Fake>() };
        let wipe_count = WIPES.get();
        assert!(wipe_count > 0);
        for reset in [false, true] {
            for at in 1..=wipe_count {
                hw(|h| h.masked = 1);
                prepare(retained);
                let receives = hw(|h| h.receives);
                let submissions = hw(|h| h.submissions);
                WIPES.set(0);
                BUS_RESET.set(reset);
                FIRED.set(false);
                INTERRUPT_AT.set(Some(at));
                hw(|h| h.masked = 0);
                unsafe { usb::service::<Fake>() };
                assert!(FIRED.get(), "{retained:?} wipe {at}/{wipe_count}");
                assert!(!hw(|h| h.ready));
                assert_eq!(hw(|h| h.receives)[1..], receives[1..]);
                // A second serialized service clears the newer lifecycle.
                unsafe { usb::service::<Fake>() };
                assert!(hw(|h| h.ready));
                for ep in usb_wire::EP_KEYBOARD..=usb_wire::EP_CCID {
                    assert_eq!(hw(|h| h.receives[endpoint(ep)]), receives[endpoint(ep)] + 1);
                }
                let armed = hw(|h| h.receives);
                unsafe { usb::service::<Fake>() };
                assert_eq!(hw(|h| h.receives), armed);
                loops();
                assert!(!pending(usb_wire::EP_CCID) && !pending(usb_wire::EP_HID));
                for ep in [usb_wire::EP_CCID, usb_wire::EP_HID] {
                    assert_eq!(
                        hw(|h| h.submissions[endpoint(ep)]),
                        submissions[endpoint(ep)]
                    );
                }
                clean_scratch();
                hw(|h| h.masked = 1);
                // Refused injected commands neither select ADMIN nor restore
                // the prior authorization/response source after cleanup.
                ccid_apdu(QUERY, 0x6a82);
                web_apdu(REST, 0x6986);
                web_apdu(SELECT_ADMIN, 0x9000);
                web_apdu(QUERY, 0x63c3);
                cases += 1;
            }
        }
        println!("USB_CLEANUP_IRQ state={retained:?} wipe_points={wipe_count} resets=2");
    }
    hw(|h| h.masked = 1);
    println!("USB_CLEANUP_IRQ cases={cases} passed");
}
