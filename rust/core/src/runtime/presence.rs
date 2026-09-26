// SPDX-License-Identifier: Apache-2.0
//! Main-loop presence operation; no C callback may reenter the core.
#![forbid(unsafe_code)]
#[cfg(persistent_applet)]
const PRESENCE_TIMEOUT_MS: u32 = 30_000;
#[cfg(persistent_applet)]
fn wait(device: &mut crate::ports::DevicePort<'_>, minimum_ms: u32) -> Result<(), Error> {
    if device.contactless() {
        return if device.progress() {
            Ok(())
        } else {
            Err(Error::Cancelled)
        };
    }
    let start = device.now();
    // A contact predating this request must be released before a fresh gesture.
    let mut armed = !device.touched();
    let mut pressed = None;
    loop {
        if !device.progress() {
            return Err(Error::Cancelled);
        }
        if device.now().wrapping_sub(start) >= PRESENCE_TIMEOUT_MS {
            return Err(Error::Timeout);
        }
        let touch = device.touched();
        if !armed {
            armed = !touch;
            continue;
        }
        if touch {
            pressed.get_or_insert_with(|| device.now());
        } else if let Some(since) = pressed.take() {
            if device.now().wrapping_sub(since) >= minimum_ms {
                return Ok(());
            }
        }
    }
}

#[cfg(persistent_applet)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Cancelled,
    Timeout,
}
#[cfg(feature = "admin")]
const SHORT_TOUCH_WINDOW_MS: u32 = 2_000;
#[cfg(any(feature = "ctap", feature = "admin"))]
const LONG_TOUCH_MS: u32 = 500;
#[cfg(feature = "admin")]
const STRONG_TOUCH_COUNT: u32 = 5;
#[cfg(feature = "admin")]
const STRONG_RELEASE_GAP_MS: u32 = SHORT_TOUCH_WINDOW_MS;
#[cfg(feature = "admin")]
const BLINK_FAST_MS: u32 = 50;
#[cfg(feature = "admin")]
const BLINK_SLOW_MS: u32 = 200;

/// Five fresh short touches, each prompted within a two-second blink window.
/// Delay after each release separates prompts; only raw transport progress runs.
#[cfg(feature = "admin")]
pub fn strong(device: &mut crate::ports::DevicePort<'_>) -> bool {
    // Factory reset requires physical gestures and is forbidden over NFC.
    if device.contactless() {
        return false;
    }
    // This deliberately remains separate from `wait`: factory reset requires
    // five released, short gestures with LED prompts between them, while
    // ordinary applet authorization accepts one gesture and no prompt.
    let accepted = (|| {
        for round in 0..STRONG_TOUCH_COUNT {
            let start = device.now();
            let mut armed = !device.touched();
            let mut pressed = None;
            loop {
                let elapsed = device.now().wrapping_sub(start);
                if elapsed >= SHORT_TOUCH_WINDOW_MS || !device.progress() {
                    return false;
                }
                let blink = if round % 2 == 0 {
                    BLINK_FAST_MS
                } else {
                    BLINK_SLOW_MS
                };
                device.led((elapsed / blink).is_multiple_of(2));
                let touch = device.touched();
                if !armed {
                    armed = !touch;
                    continue;
                }
                if touch && pressed.is_none() {
                    pressed = Some(device.now());
                }
                if !touch && let Some(since) = pressed {
                    if device.now().wrapping_sub(since) >= LONG_TOUCH_MS {
                        return false;
                    }
                    break;
                }
            }
            device.led(false);
            let released = device.now();
            while device.now().wrapping_sub(released) < STRONG_RELEASE_GAP_MS {
                if !device.progress() {
                    return false;
                }
            }
        }
        true
    })();
    device.led(false);
    accepted
}

/// An attempted request owns its gesture even when it times out or is cancelled.
#[cfg(persistent_applet)]
pub struct Request {
    attempted: bool,
}
#[cfg(persistent_applet)]
impl Request {
    pub const fn new() -> Self {
        Self { attempted: false }
    }
    #[cfg(classic_presence)]
    pub fn wait(&mut self, device: &mut crate::ports::DevicePort<'_>) -> bool {
        self.wait_result(device).is_ok()
    }
    #[cfg(feature = "ctap")]
    pub fn poll(&mut self, device: &mut crate::ports::DevicePort<'_>) -> bool {
        self.attempted = true;
        if device.contactless() {
            device.progress()
        } else {
            device.poll_presence()
        }
    }
    pub fn wait_result(&mut self, device: &mut crate::ports::DevicePort<'_>) -> Result<(), Error> {
        self.attempted = true;
        wait(device, 0)
    }
    #[cfg(feature = "ctap")]
    pub fn wait_long(&mut self, device: &mut crate::ports::DevicePort<'_>) -> Result<(), Error> {
        self.attempted = true;
        wait(device, LONG_TOUCH_MS)
    }
    #[cfg(feature = "pass")]
    pub fn take(&mut self) -> bool {
        core::mem::take(&mut self.attempted)
    }
}

#[cfg(all(
    test,
    feature = "pass",
    any(feature = "oath", feature = "openpgp", feature = "piv")
))]
mod tests {
    use super::*;
    use crate::ports::Device;
    struct Held {
        ticks: u32,
        connected: bool,
    }
    impl Device for Held {
        fn serial(&mut self, out: &mut [u8; 4]) {
            out.fill(0);
        }
        fn now(&mut self) -> u32 {
            self.ticks
        }
        fn touched(&mut self) -> bool {
            true
        }
        fn progress(&mut self) -> bool {
            self.ticks += 1000;
            self.connected
        }
        fn led(&mut self, _: bool) {}
    }
    #[test]
    fn failed_wait_still_claims_gesture() {
        for connected in [true, false] {
            let mut request = Request::new();
            assert!(!request.wait(&mut Held {
                ticks: 0,
                connected
            }));
            assert!(request.take());
            assert!(!request.take());
        }
    }
}

#[cfg(feature = "ctap")]
pub use canokey_ports::Polling;

#[cfg(all(
    test,
    feature = "ctap",
    feature = "admin",
    not(feature = "static-backend")
))]
mod contactless_tests {
    use super::*;
    struct Contactless(bool);
    impl crate::ports::Device for Contactless {
        fn serial(&mut self, _: &mut [u8; 4]) {}
        fn now(&mut self) -> u32 {
            panic!("contactless presence must not poll time")
        }
        fn touched(&mut self) -> bool {
            panic!("no touch hardware in NFC mode")
        }
        fn contactless(&mut self) -> bool {
            true
        }
        fn progress(&mut self) -> bool {
            self.0
        }
        fn led(&mut self, _: bool) {
            panic!("no LED prompts in NFC mode")
        }
    }
    #[test]
    fn contactless_presence_checks_transport_and_denies_factory_reset() {
        let mut request = Request::new();
        let mut device = Contactless(true);
        assert_eq!(request.wait_result(&mut device), Ok(()));
        assert_eq!(request.wait_long(&mut device), Ok(()));
        assert!(request.poll(&mut device));
        assert!(!strong(&mut device));
        device.0 = false;
        assert_eq!(request.wait_result(&mut device), Err(Error::Cancelled));
        assert!(!request.poll(&mut device));
    }
}
