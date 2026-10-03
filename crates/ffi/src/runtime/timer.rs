// SPDX-License-Identifier: Apache-2.0
//! One transport timer lease, disjoint from Core and its shared workspace.
use crate::transport::usb_locked;
unsafe extern "C" {
    fn ck_timer_arm(milliseconds: u16);
}
type Callback = unsafe extern "C" fn();
static mut CALLBACK: Option<Callback> = None;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_set_timeout(next: Option<Callback>, milliseconds: u16) {
    usb_locked(|| unsafe {
        ck_timer_arm(0);
        // A zero duration cancels the lease, including any stale IRQ callback.
        CALLBACK = if milliseconds == 0 { None } else { next };
        if next.is_some() && milliseconds != 0 {
            ck_timer_arm(milliseconds);
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_timer_irq() {
    let next = usb_locked(|| unsafe {
        ck_timer_arm(0);
        core::ptr::addr_of_mut!(CALLBACK).replace(None)
    });
    // Drop the old lease before calling out so the callback may rearm itself.
    // Only transport callbacks may register here: never Core/storage/crypto.
    if let Some(next) = next {
        unsafe {
            next();
        }
    }
}
