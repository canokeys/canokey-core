// SPDX-License-Identifier: Apache-2.0
//! Main-loop only, serialized, non-reentrant C boundary. RX/TX may alias.
use crate::platform::with_platform;
use canokey_rust_core::Core;
// Safety contract: the C main loop serializes every entrypoint. USB/timer
// interrupts may maintain transport state but must never borrow CORE.
// Storage lives in BSS; construct state on first main-loop access instead of
// storing a mostly-zero Core initialization image in Flash.
crate::lazy_state!(CORE, CORE_READY, Core, Core::new(), initialize_core, core);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_install() -> i32 {
    with_platform(|p| unsafe { core().install(p).map_or(-1, |_| 0) })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_reset() {
    with_platform(|p| unsafe {
        core().reset(p);
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ck_core_applet_count() -> u8 {
    Core::applet_count()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_exchange(
    owner: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    if input.is_null()
        || out.is_null()
        || len > isize::MAX as usize
        || capacity > isize::MAX as usize
        || capacity < 2
    {
        return -1;
    }
    with_platform(|p| unsafe {
        let engine = core();
        // End the immutable RX borrow before creating mutable TX: C permits
        // the input/output buffers to overlap, Rust references do not.
        let reply = engine.receive(owner, core::slice::from_raw_parts(input, len), p);
        engine
            .transmit(reply, core::slice::from_raw_parts_mut(out, capacity), p)
            .map_or(-1, |n| n as i32)
    })
}
#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_touch(index: u8, out: *mut u8, capacity: usize) -> i32 {
    if out.is_null() || capacity > isize::MAX as usize {
        return -1;
    }
    with_platform(|p| unsafe {
        core()
            .touch(index, core::slice::from_raw_parts_mut(out, capacity), p)
            .map_or(-1, |n| n as i32)
    })
}
#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_challenge(
    index: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
) -> i32 {
    const MAX_CHALLENGE_BYTES: usize = 64;
    const CHALLENGE_OUTPUT_BYTES: usize = 20;
    // The C ABI fixes the output buffer at CHALLENGE_OUTPUT_BYTES.
    if input.is_null() || out.is_null() || len > MAX_CHALLENGE_BYTES {
        return -1;
    }
    with_platform(|p| unsafe {
        let mut result = [0; CHALLENGE_OUTPUT_BYTES];
        let status = core().challenge(
            index,
            core::slice::from_raw_parts(input, len),
            &mut result,
            p,
        );
        if status.is_ok() {
            core::ptr::copy_nonoverlapping(result.as_ptr(), out, CHALLENGE_OUTPUT_BYTES);
        }
        p.memory.wipe(&mut result);
        status.map_or(-1, |_| 0)
    })
}

#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_output_sample(pressed: u8, now: u32, ready: u8) -> i32 {
    with_platform(|p| unsafe {
        core()
            .sample_output(pressed != 0, now, ready != 0, p)
            .map_or(-1, i32::from)
    })
}

// Native HID uses the same registry, authorization state and workspace as APDU.
#[cfg(feature = "ctap")]
pub(crate) fn with_core<T>(
    run: impl FnOnce(&mut Core, &mut canokey_rust_core::Platform<'_>) -> T,
) -> T {
    with_platform(|p| unsafe { run(core(), p) })
}
