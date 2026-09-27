// SPDX-License-Identifier: Apache-2.0
//! USB IRQ report mailbox and reset epochs, disjoint from CTAPHID execution.
unsafe extern "C" {
    fn ck_usb_dcd_lock() -> u32;
    fn ck_usb_dcd_unlock(mask: u32);
    fn ck_usb_configured() -> u8;
    fn ck_usb_tx_idle(endpoint: u8) -> u8;
    fn ck_usb_submit(endpoint: u8, bytes: *const u8, length: u16, zlp: u8) -> i32;
    fn ck_usb_receive(endpoint: u8);
    fn device_get_tick() -> u32;
}
static mut INCOMING: [u8; 64] = [0; 64];
static mut QUEUED: bool = false;
static mut RESET: bool = false;
static mut EPOCH: u32 = 0;
static mut RECEIVED: u32 = 0;
fn locked<T>(run: impl FnOnce() -> T) -> T {
    unsafe {
        let mask = ck_usb_dcd_lock();
        let result = run();
        ck_usb_dcd_unlock(mask);
        result
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTAPHID_RxCanAccept() -> u8 {
    unsafe { u8::from(!core::ptr::read_volatile(core::ptr::addr_of!(QUEUED))) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTAPHID_OutEvent(data: *const u8) -> u8 {
    locked(|| unsafe {
        if QUEUED || data.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(data, core::ptr::addr_of_mut!(INCOMING).cast(), 64);
        RECEIVED = device_get_tick();
        QUEUED = true;
        1
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_packet_reset() {
    locked(|| unsafe {
        EPOCH = EPOCH.wrapping_add(1);
        RESET = true;
        QUEUED = false;
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_packet_out(data: *const u8) -> u8 {
    unsafe {
        CTAPHID_OutEvent(data);
    }
    0 // Only main-loop consumption releases the FIFO.
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_epoch() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EPOCH)) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_reset_pending() -> u8 {
    unsafe { u8::from(core::ptr::read_volatile(core::ptr::addr_of!(RESET))) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_ack_reset(generation: u32) {
    locked(|| unsafe {
        if EPOCH == generation {
            RESET = false;
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_configured() -> u8 {
    locked(|| unsafe { ck_usb_configured() })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_idle() -> u8 {
    locked(|| unsafe { ck_usb_tx_idle(0x82) })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_peek(
    report: *mut u8,
    length: u8,
    tick: *mut u32,
    generation: u32,
) -> u8 {
    locked(|| unsafe {
        let ok =
            generation == EPOCH && QUEUED && length <= 64 && !report.is_null() && !tick.is_null();
        if ok {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(INCOMING).cast(),
                report,
                usize::from(length),
            );
            tick.write(RECEIVED);
        }
        u8::from(ok)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_consume(generation: u32) {
    locked(|| unsafe {
        if generation == EPOCH {
            QUEUED = false;
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_receive() {
    locked(|| unsafe {
        if !QUEUED {
            ck_usb_receive(2);
        }
    });
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_hid_io_send(report: *const u8, generation: u32) -> u8 {
    locked(|| unsafe {
        u8::from(
            generation == EPOCH
                && !RESET
                && !report.is_null()
                && ck_usb_submit(0x82, report, 64, 0) == 1,
        )
    })
}
