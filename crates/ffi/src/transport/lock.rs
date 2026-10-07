// SPDX-License-Identifier: Apache-2.0
pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(not(all(test, feature = "usb-ccid", not(feature = "usb-device"))))]
    use crate::sys::{ck_usb_dcd_lock, ck_usb_dcd_unlock};
    #[cfg(all(test, feature = "usb-ccid", not(feature = "usb-device")))]
    use crate::transport::ccid::io::tests::{ck_usb_dcd_lock, ck_usb_dcd_unlock};
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
