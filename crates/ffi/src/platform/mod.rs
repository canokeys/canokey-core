// SPDX-License-Identifier: Apache-2.0
//! C platform adapters split by capability. The safe core sees only typed ports.

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
use canokey_ports::BackendTypes;
mod storage;
use canokey_ports::native::{CryptoBackend, DeviceBackend, DeviceRuntime, MemoryBackend};
use canokey_rust_core::ports::Platform;
use storage::StorageBackend;

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub(crate) type BoundPlatform<'a> = Platform<
    'a,
    BackendTypes<StorageBackend, CryptoBackend, DeviceBackend<Runtime>, MemoryBackend>,
>;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub(crate) type BoundPlatform<'a> = Platform<'a, canokey_ports::DynamicBackends<'static>>;

pub(crate) struct Native;
impl crate::composition::Provider for Native {
    #[cfg(feature = "ctap")]
    type Staging = Scratch;
    #[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
    type Backends =
        BackendTypes<StorageBackend, CryptoBackend, DeviceBackend<Runtime>, MemoryBackend>;
    #[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
    type Backends = canokey_ports::DynamicBackends<'static>;
    fn with_platform<T>(run: impl FnOnce(&mut BoundPlatform<'_>) -> T) -> T {
        with_platform(run)
    }
}

#[cfg(feature = "ctap")]
pub(crate) struct Scratch;
#[cfg(feature = "ctap")]
impl crate::composition::Staging for Scratch {
    fn capacity() -> usize {
        unsafe { crate::sys::pke_buffer_size() }
    }
    fn acquire(owner: u8) -> bool {
        unsafe { crate::sys::pke_buffer_acquire(owner) == 0 }
    }
    fn clear() -> bool {
        unsafe { crate::sys::pke_buffer_clear() == 0 }
    }
    fn release(owner: u8) -> bool {
        unsafe { crate::sys::pke_buffer_release(owner) == 0 }
    }
    fn read(offset: usize, out: &mut [u8]) -> bool {
        unsafe { crate::sys::pke_buffer_read(offset, out.as_mut_ptr(), out.len()) == 0 }
    }
    fn write(offset: usize, bytes: &[u8]) -> bool {
        unsafe { crate::sys::pke_buffer_write(offset, bytes.as_ptr(), bytes.len()) == 0 }
    }
}

pub(crate) struct Runtime;
impl DeviceRuntime for Runtime {
    fn settings(flags: u32) {
        #[cfg(feature = "device-runtime")]
        unsafe {
            crate::runtime::device::ck_device_settings(flags)
        };
        #[cfg(not(feature = "device-runtime"))]
        let _ = flags;
    }
    fn led_idle() {
        #[cfg(feature = "device-runtime")]
        unsafe {
            crate::runtime::device::ck_device_led_idle()
        };
    }
    fn progress() -> bool {
        #[cfg(feature = "device-runtime")]
        {
            unsafe { crate::runtime::device::ck_device_progress() != 0 }
        }
        #[cfg(not(feature = "device-runtime"))]
        {
            false
        }
    }
    fn serial(out: &mut [u8; 4]) {
        #[cfg(all(feature = "device-runtime", feature = "platform-serial"))]
        unsafe {
            crate::runtime::device::ck_device_serial(out.as_mut_ptr())
        };
        #[cfg(not(all(feature = "device-runtime", feature = "platform-serial")))]
        let _ = out;
    }
    fn keepalive(waiting: bool) {
        #[cfg(feature = "usb-hid")]
        unsafe {
            crate::transport::hid::link::ck_hid_keepalive(u8::from(waiting))
        };
        #[cfg(not(feature = "usb-hid"))]
        let _ = waiting;
    }
}

#[cfg(feature = "device-runtime")]
impl crate::composition::FirmwareProvider for Native {
    #[cfg(feature = "ctap")]
    unsafe fn sample_presence() {
        #[cfg(not(test))]
        unsafe {
            ck_core_presence_sample()
        };
        #[cfg(test)]
        unsafe {
            crate::runtime::device::tests::ck_core_presence_sample()
        };
    }
}

// Retained for the C storage fixture until its platform composition moves.
#[cfg(feature = "ctap")]
#[cfg_attr(feature = "native-composition", unsafe(no_mangle))]
pub unsafe extern "C" fn ck_core_presence_sample() {
    unsafe { canokey_ports::native::presence_sample::<Runtime>() }
}

pub(crate) fn with_platform<T>(run: impl FnOnce(&mut BoundPlatform<'_>) -> T) -> T {
    // SAFETY: callers are the serialized C entrypoints or their main-loop
    // continuation. The closure cannot let any of these borrows escape.
    let (mut storage, mut crypto, mut device) = unsafe {
        (
            StorageBackend::new(),
            CryptoBackend::new(),
            DeviceBackend::<Runtime>::new(),
        )
    };
    run(&mut Platform::new(
        &mut storage,
        &mut crypto,
        &mut device,
        &MemoryBackend,
    ))
}
