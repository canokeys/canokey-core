// SPDX-License-Identifier: Apache-2.0
//! Device callbacks for the optional compatibility C composition.
use canokey_ports::Device;
use canokey_ports::contracts::board_info_kind;

/// Native platform capability, created only at the serialized FFI boundary.
/// The marker prevents transferring a borrowed hardware session across threads.
pub struct DeviceBackend<R: DeviceRuntime>(core::marker::PhantomData<(*mut (), R)>);

/// Rust-owned lifecycle hooks supplied by the outer runtime composition.
pub trait DeviceRuntime {
    #[cfg(feature = "device-runtime")]
    fn settings(flags: u32);
    #[cfg(all(feature = "device-runtime", feature = "platform-device"))]
    fn led_idle();
    #[cfg(all(feature = "device-runtime", feature = "platform-device"))]
    fn progress() -> bool;
    #[cfg(all(feature = "device-runtime", feature = "platform-serial"))]
    fn serial(out: &mut [u8; 4]);
    #[cfg(feature = "ctap")]
    fn keepalive(waiting: bool);
}

impl<R: DeviceRuntime> DeviceBackend<R> {
    /// # Safety
    /// All native platform access, including callbacks and other backend values,
    /// must remain serialized for this value's entire lifetime. Native global
    /// storage, crypto scratch and presence state are not independently locked.
    pub unsafe fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}
#[cfg(feature = "device-runtime")]
unsafe extern "C" {
    fn ck_board_info(kind: u8, length: *mut usize) -> *const u8;
    fn ck_board_chip_id(output: *mut u8);
    fn ck_board_recovery_word() -> u32;
}
#[cfg(feature = "platform-device")]
fn idle_led<R: DeviceRuntime>() {
    #[cfg(feature = "device-runtime")]
    R::led_idle();
    #[cfg(not(feature = "device-runtime"))]
    // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
    unsafe {
        ck_platform_led(0);
    }
}

#[cfg(feature = "nfc")]
use crate::transport::nfc::is_nfc;

#[cfg(feature = "platform-device")]
unsafe extern "C" {
    fn ck_platform_now() -> u32;
    fn ck_platform_touched() -> u8;
    #[cfg(not(feature = "device-runtime"))]
    fn ck_platform_progress() -> u8;
    fn ck_platform_led(on: u8);
}
#[cfg(feature = "platform-serial")]
unsafe extern "C" {
    #[cfg(not(feature = "device-runtime"))]
    fn ck_platform_serial(out: *mut u8);
}
#[cfg(feature = "ctap")]
// Keep the independent polling latch out of LLVM's merged transport globals.
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.ck_device_presence"))]
static mut PRESENCE: canokey_ports::Polling = canokey_ports::Polling::new();

// Main loop only, including while neither transport owns a core session.
#[cfg(all(feature = "ctap", feature = "native-platform"))]
pub unsafe fn presence_sample<R: DeviceRuntime>() {
    #[cfg(feature = "nfc")]
    // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
    if unsafe { is_nfc() != 0 } {
        return;
    }
    // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
    unsafe {
        let poll = &mut *core::ptr::addr_of_mut!(PRESENCE);
        if let Some(on) = poll.sample(ck_platform_touched() != 0, ck_platform_now()) {
            if !poll.prompt_active() {
                idle_led::<R>();
            } else {
                ck_platform_led(u8::from(on));
            }
        }
    }
}
impl<R: DeviceRuntime> Device for DeviceBackend<R> {
    fn recovery_word(&mut self) -> Option<u32> {
        #[cfg(feature = "device-runtime")]
        {
            // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
            Some(unsafe { ck_board_recovery_word() })
        }
        #[cfg(not(feature = "device-runtime"))]
        {
            None
        }
    }

    fn information(&mut self, kind: u8, output: &mut [u8]) -> usize {
        #[cfg(feature = "device-runtime")]
        {
            if kind == board_info_kind::CHIP_ID {
                let mut id = [0; canokey_ports::contracts::CHIP_ID_BYTES];
                // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
                unsafe {
                    ck_board_chip_id(id.as_mut_ptr());
                }
                let len = output.len().min(id.len());
                output[..len].copy_from_slice(&id[..len]);
                return len;
            }
            let mut len = 0;
            // SAFETY: The board fills the live length out-parameter and returns a borrowed board-table pointer.
            let data = unsafe { ck_board_info(kind, &mut len) };
            if data.is_null() {
                return 0;
            }
            let len = len.min(output.len());
            // SAFETY: The board table owns the returned bytes; the null check and copy bound precede the borrow.
            output[..len].copy_from_slice(unsafe { core::slice::from_raw_parts(data, len) });
            len
        }
        #[cfg(not(feature = "device-runtime"))]
        {
            // Unconfigured host tools retain zero identity; USB/IP supplies release fields.
            let data: &[u8] = match kind {
                board_info_kind::FIRMWARE => option_env!("CANOKEY_ADMIN_VERSION")
                    .unwrap_or("0.0.0")
                    .as_bytes(),
                board_info_kind::PRODUCT => b"CanoKey Rust Virtual Card",
                board_info_kind::CHIP_ID => &[0; canokey_ports::contracts::CHIP_ID_BYTES],
                _ => option_env!("CANOKEY_CORE_SHA")
                    .unwrap_or("unknown")
                    .as_bytes(),
            };
            let len = output.len().min(data.len());
            output[..len].copy_from_slice(&data[..len]);
            len
        }
    }

    fn configuration_changed(&mut self, flags: u32) {
        #[cfg(feature = "device-runtime")]
        R::settings(flags);
        #[cfg(not(feature = "device-runtime"))]
        let _ = flags;
    }
    fn led_idle(&mut self) {
        #[cfg(feature = "platform-device")]
        idle_led::<R>();
    }
    fn contactless(&mut self) -> bool {
        #[cfg(feature = "nfc")]
        {
            // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
            unsafe { is_nfc() != 0 }
        }
        #[cfg(not(feature = "nfc"))]
        {
            false
        }
    }
    #[cfg(feature = "ctap")]
    fn wink(&mut self) {
        // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
        unsafe {
            (&mut *core::ptr::addr_of_mut!(PRESENCE)).wink(ck_platform_now());
        }
    }
    #[cfg(feature = "ctap")]
    fn poll_presence(&mut self) -> bool {
        // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
        unsafe {
            let accepted = (&mut *core::ptr::addr_of_mut!(PRESENCE)).take(ck_platform_now());
            if accepted {
                idle_led::<R>();
            }
            accepted
        }
    }
    fn keepalive(&mut self, waiting: bool) {
        #[cfg(feature = "nfc")]
        // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
        if unsafe { is_nfc() != 0 } {
            return;
        }
        #[cfg(feature = "ctap")]
        R::keepalive(waiting);
        #[cfg(not(feature = "ctap"))]
        let _ = waiting;
    }
    fn serial(&mut self, out: &mut [u8; 4]) {
        #[cfg(feature = "platform-serial")]
        {
            #[cfg(feature = "device-runtime")]
            R::serial(out);
            #[cfg(not(feature = "device-runtime"))]
            // SAFETY: Serial output uses the caller's fixed four-byte buffer on the serialized board loop.
            unsafe {
                ck_platform_serial(out.as_mut_ptr())
            }
        }
        #[cfg(not(feature = "platform-serial"))]
        {
            // Partial profiles have no serial provider; the caller's initialized
            // fallback remains untouched because this infallible ABI has no status.
            let _ = out;
        }
    }
    fn now(&mut self) -> u32 {
        #[cfg(feature = "platform-device")]
        {
            // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
            unsafe { ck_platform_now() }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            0
        }
    }
    fn touched(&mut self) -> bool {
        #[cfg(feature = "ctap")]
        // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
        unsafe {
            (&mut *core::ptr::addr_of_mut!(PRESENCE)).clear();
        }
        #[cfg(feature = "platform-device")]
        {
            // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
            unsafe { ck_platform_touched() != 0 }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            false
        }
    }
    fn progress(&mut self) -> bool {
        #[cfg(feature = "platform-device")]
        {
            #[cfg(feature = "device-runtime")]
            {
                R::progress()
            }
            #[cfg(not(feature = "device-runtime"))]
            {
                // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
                unsafe { ck_platform_progress() != 0 }
            }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = ();
            false
        }
    }
    fn led(&mut self, on: bool) {
        #[cfg(feature = "nfc")]
        // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
        if on && unsafe { is_nfc() != 0 } {
            return;
        }
        #[cfg(feature = "platform-device")]
        {
            // SAFETY: The device adapter is used by the serialized board loop with its callbacks installed.
            unsafe { ck_platform_led(u8::from(on)) }
        }
        #[cfg(not(feature = "platform-device"))]
        {
            let _ = on;
        }
    }
}
