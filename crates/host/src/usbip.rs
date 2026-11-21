// SPDX-License-Identifier: Apache-2.0
//! USB/IP enters the same serialized applet runtime as the physical USB device.
use super::*;
use canokey_rust_ffi::composition::usb;

#[unsafe(no_mangle)]
unsafe extern "C" fn ck_host_usbip_open(path: *const std::ffi::c_char, touch: u8) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if path.is_null() || HOST.lock().unwrap().is_some() {
        return -1;
    }
    // SAFETY: The caller supplies a live, NUL-terminated C path for the duration of this call.
    let Ok(path) = (unsafe { std::ffi::CStr::from_ptr(path) }).to_str() else {
        return -1;
    };
    if let Err(error) = initialize_storage(None, path, false, true) {
        eprintln!("USB/IP storage: {error}");
        HOST.lock().unwrap().take();
        return -1;
    }
    // Presence simulation is explicit, confined to the host, and uses real timing.
    if touch != 0 {
        if std::fs::write("/tmp/canokey-test-up", "1000000\n").is_err() {
            HOST.lock().unwrap().take();
            return -1;
        }
    }
    // SAFETY: The single-threaded host uses its installed Provider without reentering Core.
    unsafe { usb::init() };
    0
}

#[unsafe(no_mangle)]
extern "C" fn ck_host_usbip_loop() {
    let _entry = ENTRY.lock().unwrap();
    // SAFETY: The single-threaded host uses its installed Provider without reentering Core.
    unsafe {
        presence_sample();
        canokey_rust_ffi::composition::ccid::poll::<HostProvider>();
        hid::poll::<HostProvider>();
        canokey_rust_ffi::composition::webusb::poll::<HostProvider>();
    }
}
