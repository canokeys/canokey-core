// SPDX-License-Identifier: Apache-2.0
//! C platform adapters split by capability. The safe core sees only typed ports.

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
use canokey_ports::BackendTypes;
mod device;
mod storage;
use canokey_native_crypto::CryptoBackend;
use canokey_ports::MemoryBackend;
use canokey_rust_core::ports::Platform;
use device::{DeviceBackend, DeviceRuntime};
use storage::StorageBackend;

#[cfg(all(feature = "static-backend", not(feature = "dynamic-backend")))]
pub(crate) type BoundPlatform<'a> = Platform<
    'a,
    BackendTypes<StorageBackend, CryptoBackend, DeviceBackend<Runtime>, MemoryBackend>,
>;
#[cfg(not(all(feature = "static-backend", not(feature = "dynamic-backend"))))]
pub(crate) type BoundPlatform<'a> = Platform<'a, canokey_ports::DynamicBackends<'static>>;

pub struct Native;
#[cfg(all(feature = "ctap", feature = "native-platform"))]
impl Native {
    /// # Safety
    /// Sample only on the serialized main loop, outside active Core calls.
    pub unsafe fn sample_presence() {
        unsafe { device::presence_sample::<Runtime>() }
    }
}
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
pub struct Scratch;
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

pub struct Runtime;
impl DeviceRuntime for Runtime {
    #[cfg(feature = "device-runtime")]
    fn settings(flags: u32) {
        unsafe { crate::runtime::device::ck_device_settings(flags) };
    }
    #[cfg(all(feature = "device-runtime", feature = "platform-device"))]
    fn led_idle() {
        unsafe { crate::runtime::device::ck_device_led_idle() };
    }
    #[cfg(all(feature = "device-runtime", feature = "platform-device"))]
    fn progress() -> bool {
        unsafe { crate::runtime::device::progress::<Native>() != 0 }
    }
    #[cfg(all(feature = "device-runtime", feature = "platform-serial"))]
    fn serial(out: &mut [u8; 4]) {
        unsafe { crate::runtime::device::serial::<Native>(out.as_mut_ptr()) };
    }
    #[cfg(feature = "ctap")]
    fn keepalive(waiting: bool) {
        #[cfg(feature = "usb-hid")]
        unsafe {
            crate::transport::hid::link::ck_hid_keepalive(u8::from(waiting))
        };
        #[cfg(not(feature = "usb-hid"))]
        let _ = waiting;
    }
}

#[cfg(all(feature = "device-runtime", feature = "storage"))]
fn storage_status(
    value: i32,
    failure: canokey_ports::StorageError,
) -> Result<(), canokey_ports::StorageError> {
    if value == 0 { Ok(()) } else { Err(failure) }
}

#[cfg(feature = "device-runtime")]
impl crate::composition::FirmwareProvider for Native {
    unsafe fn storage_mount() -> Result<(), canokey_ports::StorageError> {
        #[cfg(all(feature = "storage", not(test)))]
        unsafe {
            return storage_status(
                crate::sys::ck_storage_init(),
                canokey_ports::StorageError::Unavailable,
            );
        }
        #[cfg(all(feature = "storage", test))]
        unsafe {
            return storage_status(
                crate::runtime::device::tests::hal::ck_storage_init(),
                canokey_ports::StorageError::Unavailable,
            );
        }
        #[cfg(not(feature = "storage"))]
        {
            Ok(())
        }
    }
    unsafe fn storage_format() -> Result<(), canokey_ports::StorageError> {
        #[cfg(all(feature = "storage", not(test)))]
        unsafe {
            return storage_status(
                crate::sys::ck_storage_format(),
                canokey_ports::StorageError::Uncertain,
            );
        }
        #[cfg(all(feature = "storage", test))]
        unsafe {
            return storage_status(
                crate::runtime::device::tests::hal::ck_storage_format(),
                canokey_ports::StorageError::Uncertain,
            );
        }
        #[cfg(not(feature = "storage"))]
        {
            Ok(())
        }
    }
    #[cfg(feature = "ctap")]
    unsafe fn sample_presence() {
        #[cfg(not(test))]
        unsafe {
            device::presence_sample::<Runtime>()
        };
        #[cfg(test)]
        unsafe {
            crate::runtime::device::tests::ck_core_presence_sample()
        };
    }
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
