// SPDX-License-Identifier: Apache-2.0
//! Serialized shared Core operations with outer-selected capabilities. RX/TX may alias.
use super::Provider;
#[cfg(feature = "pass")]
use canokey_ports::Memory;
use canokey_rust_core::Core;
// Safety contract: the C main loop serializes every entrypoint. USB/timer
// interrupts may maintain transport state but must never borrow CORE.
// Storage lives in BSS; construct state on first main-loop access instead of
// storing a mostly-zero Core initialization image in Flash.
crate::lazy_state!(CORE, CORE_READY, Core, Core::new(), initialize_core, core);
/// Serialized main-loop query. Never call from an IRQ or a progress callback
/// while Core is executing; it would overlap the active mutable borrow.
#[cfg(feature = "usb-ccid")]
pub unsafe fn can_preempt() -> bool {
    unsafe { core().can_preempt() }
}
pub unsafe fn install<P: Provider>() -> i32 {
    P::with_platform(|p| unsafe { core().install(p).map_or(-1, |_| 0) })
}
pub unsafe fn reset<P: Provider>() {
    P::with_platform(|p| unsafe {
        core().reset(p);
    })
}
/// Reader logical power only; USB/device reset must use ck_core_reset.
pub unsafe fn slot_power<P: Provider>() {
    P::with_platform(|p| unsafe { core().slot_power(p) })
}
pub fn applet_count() -> u8 {
    Core::applet_count()
}
pub unsafe fn exchange<P: Provider>(
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
        || capacity < canokey_protocol::apdu::STATUS_BYTES
    {
        return -1;
    }
    P::with_platform(|p| unsafe {
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
pub unsafe fn touch<P: Provider>(index: u8, out: *mut u8, capacity: usize) -> i32 {
    if out.is_null() || capacity > isize::MAX as usize {
        return -1;
    }
    P::with_platform(|p| unsafe {
        core()
            .touch(index, core::slice::from_raw_parts_mut(out, capacity), p)
            .map_or(-1, |n| n as i32)
    })
}
#[cfg(feature = "pass")]
pub unsafe fn challenge<P: Provider>(index: u8, input: *const u8, len: usize, out: *mut u8) -> i32 {
    const MAX_CHALLENGE_BYTES: usize = 64;
    const CHALLENGE_OUTPUT_BYTES: usize = 20;
    // The C ABI fixes the output buffer at CHALLENGE_OUTPUT_BYTES.
    if input.is_null() || out.is_null() || len > MAX_CHALLENGE_BYTES {
        return -1;
    }
    P::with_platform(|p| unsafe {
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
pub unsafe fn output_cancel<P: Provider>(pressed: u8) {
    P::with_platform(|p| unsafe { core().cancel_output(pressed != 0, p) })
}

#[cfg(feature = "pass")]
pub unsafe fn output_sample<P: Provider>(pressed: u8, now: u32, ready: u8) -> i32 {
    P::with_platform(|p| unsafe {
        core()
            .sample_output(pressed != 0, now, ready != 0, p)
            .map_or(-1, i32::from)
    })
}

// Main-loop only, after keyboard session arbitration. Config reads do not
// retain the shared APDU or crypto workspace.
#[cfg(feature = "pass")]
pub fn keyboard_usage<P: Provider>(ch: u8) -> i32 {
    P::with_platform(|p| {
        canokey_rust_core::runtime::config::keyboard_usage(p.storage, ch).map_or(
            -1,
            |(modifier, usage)| {
                // Keyboard ABI: modifier in high byte, HID usage in low byte.
                (i32::from(modifier) << 8) | i32::from(usage)
            },
        )
    })
}

// Native HID uses the same registry, authorization state and workspace as APDU.
#[cfg(feature = "ctap")]
pub fn with_core<P: Provider, T>(
    run: impl FnOnce(&mut Core, &mut canokey_ports::Platform<'_, P::Backends>) -> T,
) -> T {
    P::with_platform(|p| unsafe { run(core(), p) })
}

#[cfg(all(feature = "device-runtime", not(test)))]
pub fn boot_flags<P: Provider>() -> Result<u32, canokey_ports::StorageError> {
    P::with_platform(|p| canokey_rust_core::runtime::config::flags(p.storage))
}
#[cfg(all(feature = "device-runtime", feature = "storage", not(test)))]
pub fn mark_initialized<P: Provider>() -> Result<(), canokey_ports::StorageError> {
    use canokey_rust_core::runtime::config;
    P::with_platform(|p| config::update(p.storage, config::INITIALIZED, config::INITIALIZED))
}
