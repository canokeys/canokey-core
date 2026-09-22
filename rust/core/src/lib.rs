// SPDX-License-Identifier: Apache-2.0
//! Independent Rust core. No C dispatcher, session manager or applet is linked.
#![no_std]
#[cfg(feature = "pass")]
mod auth;
pub mod engine;
#[cfg(feature = "c-interface")]
mod interface;
#[cfg(feature = "pass")]
mod pass;
pub use engine::{Core, Platform, Reply};

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
