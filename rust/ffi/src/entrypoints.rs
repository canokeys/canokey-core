// SPDX-License-Identifier: Apache-2.0
//! Main-loop only, serialized, non-reentrant C boundary. RX/TX may alias.
use crate::platform::with_platform;
use canokey_rust_core::Core;
static mut CORE: Core = Core::new();
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_install() -> i32 {
    with_platform(|p| unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE))
            .install(p)
            .map_or(-1, |_| 0)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_reset() {
    with_platform(|p| unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE)).reset(p);
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
        let engine = &mut *core::ptr::addr_of_mut!(CORE);
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
        (&*core::ptr::addr_of!(CORE))
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
    if input.is_null() || out.is_null() || len > 64 {
        return -1;
    }
    with_platform(|p| unsafe {
        let mut result = [0; 20];
        let status = (&*core::ptr::addr_of!(CORE)).challenge(
            index,
            core::slice::from_raw_parts(input, len),
            &mut result,
            p,
        );
        if status.is_ok() {
            core::ptr::copy_nonoverlapping(result.as_ptr(), out, 20);
        }
        p.memory.wipe(&mut result);
        status.map_or(-1, |_| 0)
    })
}

#[cfg(feature = "pass")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ck_core_output_sample(pressed: u8, now: u32, ready: u8) -> i32 {
    with_platform(|p| unsafe {
        (&mut *core::ptr::addr_of_mut!(CORE))
            .sample_output(pressed != 0, now, ready != 0, p)
            .map_or(-1, i32::from)
    })
}
