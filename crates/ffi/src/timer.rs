// SPDX-License-Identifier: Apache-2.0
//! One transport timer lease, disjoint from Core and its shared workspace.
unsafe extern "C" {
    fn ck_timer_arm(milliseconds: u16);
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
}
type Callback = unsafe extern "C" fn();
static mut CALLBACK: Option<Callback> = None;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_set_timeout(next: Option<Callback>, milliseconds: u16) {
    unsafe {
        let mask = ck_usb_dcd_lock();
        ck_timer_arm(0);
        // A zero duration cancels the lease, including any stale IRQ callback.
        CALLBACK = if milliseconds == 0 { None } else { next };
        if next.is_some() && milliseconds != 0 {
            ck_timer_arm(milliseconds);
        }
        ck_usb_dcd_unlock(mask);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_timer_irq() {
    let next = unsafe {
        let mask = ck_usb_dcd_lock();
        ck_timer_arm(0);
        let next = core::ptr::addr_of_mut!(CALLBACK).replace(None);
        ck_usb_dcd_unlock(mask);
        next
    };
    // Drop the old lease before calling out so the callback may rearm itself.
    // Only transport callbacks may register here: never Core/storage/crypto.
    if let Some(next) = next {
        unsafe {
            next();
        }
    }
}
