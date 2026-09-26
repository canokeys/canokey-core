// SPDX-License-Identifier: Apache-2.0
//! IRQ mailbox and timed CCID extension lease, disjoint from Core execution.
unsafe extern "C" {
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
    fn ck_usb_configured() -> u8;
    fn ck_usb_tx_idle(endpoint: u8) -> u8;
    fn ck_usb_submit(endpoint: u8, bytes: *const u8, length: u16, zlp: u8) -> i32;
    fn ck_usb_receive(endpoint: u8);
    fn device_get_tick() -> u32;
    fn device_set_timeout(callback: Option<unsafe extern "C" fn()>, milliseconds: u16);
}
static mut RX: [u8; 64] = [0; 64];
static mut REPEAT: [u8; 16] = [0; 16];
static mut GENERATION: u32 = 0;
static mut RX_TICK: u32 = 0;
static mut REPEAT_GENERATION: u32 = 0;
static mut QUEUED: u8 = 0;
static mut REPEATING: bool = false;
static mut REPEAT_LENGTH: u8 = 0;
static mut REPEAT_INTERVAL: u16 = 0;
fn locked<T>(run: impl FnOnce() -> T) -> T {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_generation() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GENERATION)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_now() -> u32 {
    unsafe { device_get_tick() }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_pending() -> u8 {
    unsafe { u8::from(core::ptr::read_volatile(core::ptr::addr_of!(QUEUED)) != 0) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_peek() -> i32 {
    locked(|| unsafe { if QUEUED != 0 { i32::from(RX[0]) } else { -1 } })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_idle() -> u8 {
    locked(|| unsafe { ck_usb_tx_idle(0x83) })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_live() -> u8 {
    locked(|| unsafe {
        u8::from(REPEATING && REPEAT_GENERATION == GENERATION && ck_usb_configured() != 0)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_submit(
    epoch: u32,
    bytes: *const u8,
    length: u16,
    zlp: u8,
) -> i32 {
    locked(|| unsafe {
        if epoch != GENERATION || (bytes.is_null() && length != 0) {
            -1
        } else {
            ck_usb_submit(0x83, bytes, length, zlp)
        }
    })
}
unsafe extern "C" fn repeat_tick() {
    locked(|| unsafe {
        if ck_ccid_io_live() != 0 {
            ck_ccid_io_submit(
                REPEAT_GENERATION,
                core::ptr::addr_of!(REPEAT).cast(),
                u16::from(REPEAT_LENGTH),
                0,
            );
            device_set_timeout(Some(repeat_tick), REPEAT_INTERVAL);
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_arm(epoch: u32, bytes: *const u8, length: u8, interval: u16) {
    locked(|| unsafe {
        // Never replace bytes retained by an in-flight extension transfer.
        if epoch == GENERATION
            && ck_usb_tx_idle(0x83) != 0
            && length <= 16
            && interval != 0
            && !bytes.is_null()
        {
            core::ptr::copy_nonoverlapping(
                bytes,
                core::ptr::addr_of_mut!(REPEAT).cast(),
                usize::from(length),
            );
            REPEAT_LENGTH = length;
            REPEAT_INTERVAL = interval;
            REPEAT_GENERATION = epoch;
            REPEATING = true;
            device_set_timeout(Some(repeat_tick), interval);
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_disarm() {
    locked(|| unsafe {
        if REPEATING {
            device_set_timeout(None, 0);
        }
        REPEATING = false;
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_packet_reset() {
    locked(|| unsafe {
        if REPEATING {
            device_set_timeout(None, 0);
        }
        GENERATION = GENERATION.wrapping_add(1);
        QUEUED = 0;
        REPEATING = false;
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_packet_out(bytes: *const u8, length: u16) -> u8 {
    if length == 0 {
        return 1;
    }
    locked(|| unsafe {
        if QUEUED != 0 || length > 64 || bytes.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(
            bytes,
            core::ptr::addr_of_mut!(RX).cast(),
            usize::from(length),
        );
        RX_TICK = device_get_tick();
        QUEUED = length as u8;
        0
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_io_take(epoch: u32, output: *mut u8, tick: *mut u32) -> i32 {
    locked(|| unsafe {
        if epoch != GENERATION || output.is_null() || tick.is_null() {
            return -1;
        }
        let n = QUEUED;
        if n != 0 {
            core::ptr::copy_nonoverlapping(core::ptr::addr_of!(RX).cast(), output, usize::from(n));
            tick.write(RX_TICK);
            QUEUED = 0;
            ck_usb_receive(3);
        }
        i32::from(n)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_ccid_progress() -> u8 {
    unsafe { ck_ccid_io_live() }
}

/// Take only a complete, bodyless slot poll. Other commands stay queued for
/// the main loop; a progress callback must never trigger Core dispatch/reset.
#[cfg(all(feature = "usb-device", feature = "usb-hid"))]
pub unsafe fn take_presence(epoch: u32, output: &mut [u8; 10]) -> bool {
    locked(|| unsafe {
        if epoch != GENERATION || QUEUED != 10 || RX[0] != 0x65 || RX[1..5] != [0; 4] {
            return false;
        }
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(RX).cast(), output.as_mut_ptr(), 10);
        QUEUED = 0;
        ck_usb_receive(3);
        true
    })
}
