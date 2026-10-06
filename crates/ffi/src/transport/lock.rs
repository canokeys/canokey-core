// SPDX-License-Identifier: Apache-2.0
pub(crate) fn usb_locked<T>(run: impl FnOnce() -> T) -> T {
    use crate::sys::ck_usb_dcd_lock;
    use crate::sys::ck_usb_dcd_unlock;
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
