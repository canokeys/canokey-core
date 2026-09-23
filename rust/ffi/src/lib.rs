// SPDX-License-Identifier: Apache-2.0
#![no_std]
mod entrypoints;
mod platform;
pub use canokey_rust_core::*;
#[cfg(all(feature = "host-runtime", target_os = "none"))]
compile_error!("host-runtime must not be enabled in firmware");
#[cfg(all(feature = "host-runtime", not(test)))]
unsafe extern "C" {
    fn abort() -> !;
}
#[cfg(all(feature = "host-runtime", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
#[cfg(all(feature = "host-runtime", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() -> ! {
    unsafe { abort() }
}
