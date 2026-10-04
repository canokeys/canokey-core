// SPDX-License-Identifier: Apache-2.0
pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
    unsafe extern "C" {
        fn ck_usb_dcd_lock() -> u32;
        fn ck_usb_dcd_unlock(mask: u32);
    }
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
