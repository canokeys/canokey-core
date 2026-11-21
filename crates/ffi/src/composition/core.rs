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
///
/// # Safety
/// Use the serialized main loop outside any Core operation or progress callback.
pub unsafe fn can_preempt() -> bool {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
    unsafe { core().can_preempt() }
}
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn install<P: Provider>() -> i32 {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
    P::with_platform(|p| unsafe { core().install(p).map_or(-1, |_| 0) })
}
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn reset<P: Provider>() {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
    P::with_platform(|p| unsafe {
        core().reset(p);
    })
}
/// Reader logical power only; USB/device reset must use ck_core_reset.
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn slot_power<P: Provider>() {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
    P::with_platform(|p| unsafe { core().slot_power(p) })
}
pub fn applet_count() -> u8 {
    Core::applet_count()
}
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
/// The input must be readable for `len` bytes and output writable for `capacity` bytes. Their regions may overlap.
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
    // SAFETY: The caller supplies both live regions; RX ends before the possibly overlapping TX borrow.
    P::with_platform(|p| unsafe {
        let engine = core();
        // End the immutable RX borrow before creating mutable TX: C permits
        // the input/output buffers to overlap, Rust references do not.
        let reply = engine.receive(owner, core::slice::from_raw_parts(input, len), p);
        engine
            .transmit(reply, core::slice::from_raw_parts_mut(out, capacity), p)
            .map_or(-1, |n| i32::try_from(n).unwrap())
    })
}
#[cfg(feature = "pass")]
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
/// The output must be writable for `capacity` bytes for this call.
pub unsafe fn touch<P: Provider>(index: u8, out: *mut u8, capacity: usize) -> i32 {
    if out.is_null() || capacity > isize::MAX as usize {
        return -1;
    }
    // SAFETY: The caller guarantees the validated buffer extents and exclusive access to Core.
    P::with_platform(|p| unsafe {
        core()
            .touch(index, core::slice::from_raw_parts_mut(out, capacity), p)
            .map_or(-1, |n| i32::try_from(n).unwrap())
    })
}
#[cfg(feature = "pass")]
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
/// The input must be readable for `len` bytes and the output writable for 20 bytes.
pub unsafe fn challenge<P: Provider>(index: u8, input: *const u8, len: usize, out: *mut u8) -> i32 {
    const MAX_CHALLENGE_BYTES: usize = 64;
    const CHALLENGE_OUTPUT_BYTES: usize = 20;
    // The C ABI fixes the output buffer at CHALLENGE_OUTPUT_BYTES.
    if input.is_null() || out.is_null() || len > MAX_CHALLENGE_BYTES {
        return -1;
    }
    // SAFETY: The caller guarantees the validated buffer extents and exclusive access to Core.
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
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn output_cancel<P: Provider>(pressed: u8) {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
    P::with_platform(|p| unsafe { core().cancel_output(pressed != 0, p) })
}

#[cfg(feature = "pass")]
///
/// # Safety
/// Use the installed Provider on the serialized main loop, outside any existing Core borrow.
pub unsafe fn output_sample<P: Provider>(pressed: u8, now: u32, ready: u8) -> i32 {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
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

/// Borrow the shared APDU/HID Core with the installed runtime's capabilities.
///
/// # Safety
/// All Core access must be serialized by the outer runtime owner with the same
/// Provider for the runtime's lifetime. The callback, including its device/progress
/// callbacks, must not reenter Core or retain a Core/platform borrow.
///
/// Safe callers cannot enter the global mutable runtime:
/// ```compile_fail,E0133
/// use canokey_rust_ffi::composition::{Provider, core::with_core};
/// fn unguarded<P: Provider>() {
///     with_core::<P, _>(|_, _| ());
/// }
/// ```
#[cfg(any(feature = "ctap", feature = "nfc", feature = "usb-webusb"))]
pub unsafe fn with_core<P: Provider, T>(
    run: impl FnOnce(&mut Core, &mut canokey_ports::Platform<'_, P::Backends>) -> T,
) -> T {
    // SAFETY: The serialized main loop owns Core, and this call uses the installed Provider.
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
