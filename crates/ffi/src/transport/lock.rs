// SPDX-License-Identifier: Apache-2.0
pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(not(all(
        test,
        any(feature = "usb-ccid", feature = "usb-hid"),
        not(feature = "usb-device")
    )))]
    use crate::sys::{ck_usb_dcd_lock, ck_usb_dcd_unlock};
    #[cfg(all(
        test,
        feature = "usb-ccid",
        not(feature = "usb-device"),
        not(feature = "usb-hid")
    ))]
    use crate::transport::ccid::io::tests::{ck_usb_dcd_lock, ck_usb_dcd_unlock};
    #[cfg(all(test, feature = "usb-hid", not(feature = "usb-device")))]
    use crate::transport::hid::link::tests::{ck_usb_dcd_lock, ck_usb_dcd_unlock};
    // SAFETY: The board lock masks USB interrupts and restores the returned mask after the closure.
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
