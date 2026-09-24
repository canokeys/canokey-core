// SPDX-License-Identifier: Apache-2.0
//! Main-loop only, serialized, non-reentrant C boundary. RX/TX may alias.
use crate::platform::with_platform;
use canokey_rust_core::Core;
#[cfg(feature = "ctap")]
const OWNER_CCID: u8 = 1;
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

// Source callbacks only read/close staged bytes; they must not reenter Rust or
// perform crypto. receive_source closes the lease before applet finalization.
#[cfg(feature = "ctap")]
unsafe extern "C" {
    fn ck_ccid_source_read(offset: usize, output: *mut u8, length: usize) -> i32;
    fn ck_ccid_source_close();
}
#[cfg(feature = "ctap")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_extended_begin(prefix: *const [u8; 7], total: usize) -> i32 {
    if prefix.is_null() || total > isize::MAX as usize {
        return -1;
    }
    with_platform(|p| unsafe {
        core()
            .prepare_extended(OWNER_CCID, &*prefix, total, p)
            .map_or_else(|sw| -i32::from(sw.0), i32::from)
    })
}
#[cfg(feature = "ctap")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_exchange_ccid_source(
    total: usize,
    output: *mut u8,
    capacity: usize,
) -> i32 {
    use canokey_protocol::response::StatusWord as Sw;
    use canokey_rust_core::runtime::engine::InputSource;
    if output.is_null()
        || total > isize::MAX as usize
        || capacity > isize::MAX as usize
        || capacity < 2
    {
        return -1;
    }
    struct Request {
        offset: usize,
    }
    impl InputSource for Request {
        fn read(&mut self, out: &mut [u8]) -> Result<usize, Sw> {
            if unsafe { ck_ccid_source_read(self.offset, out.as_mut_ptr(), out.len()) } != 0 {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            self.offset += out.len();
            Ok(out.len())
        }
        fn close(&mut self) {
            unsafe {
                ck_ccid_source_close();
            }
        }
    }
    with_platform(|p| unsafe {
        let engine = core();
        let reply = engine.receive_source(OWNER_CCID, total, &mut Request { offset: 0 }, p);
        engine
            .transmit(reply, core::slice::from_raw_parts_mut(output, capacity), p)
            .map_or(-1, |n| n as i32)
    })
}

// Native HID uses the same registry, authorization state and workspace as APDU.
#[cfg(feature = "ctap")]
pub(crate) fn with_core<T>(
    run: impl FnOnce(&mut Core, &mut canokey_rust_core::Platform<'_>) -> T,
) -> T {
    with_platform(|p| unsafe { run(core(), p) })
}
