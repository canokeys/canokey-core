// SPDX-License-Identifier: Apache-2.0
//! Main-loop presence operation; no C callback may reenter the core.
#![forbid(unsafe_code)]
use crate::ports::Device;
#[cfg(any(feature = "oath", feature = "openpgp"))]
fn wait(device: &mut dyn Device) -> bool {
    let start = device.now();
    // A contact predating this request must be released before a fresh gesture.
    let mut armed = !device.touched();
    let mut pressed = false;
    loop {
        if !device.progress() || device.now().wrapping_sub(start) >= 30_000 {
            return false;
        }
        let touch = device.touched();
        if !armed {
            armed = !touch;
            continue;
        }
        if touch {
            pressed = true;
        }
        if pressed && !touch {
            return true;
        }
    }
}

/// Five fresh short touches, each prompted within a two-second blink window.
/// Delay after each release separates prompts; only raw transport progress runs.
#[cfg(feature = "admin")]
pub fn strong(device: &mut dyn Device) -> bool {
    let accepted = (|| {
        for round in 0..5 {
            let start = device.now();
            let mut armed = !device.touched();
            let mut pressed = None;
            loop {
                let elapsed = device.now().wrapping_sub(start);
                if elapsed >= 2000 || !device.progress() {
                    return false;
                }
                device.led((elapsed / if round % 2 == 0 { 50 } else { 200 }).is_multiple_of(2));
                let touch = device.touched();
                if !armed {
                    armed = !touch;
                    continue;
                }
                if touch && pressed.is_none() {
                    pressed = Some(device.now());
                }
                if !touch && let Some(since) = pressed {
                    if device.now().wrapping_sub(since) >= 500 {
                        return false;
                    }
                    break;
                }
            }
            device.led(false);
            let released = device.now();
            while device.now().wrapping_sub(released) < 2000 {
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
#[cfg(any(feature = "oath", feature = "openpgp"))]
pub struct Request {
    attempted: bool,
}
#[cfg(any(feature = "oath", feature = "openpgp"))]
impl Request {
    pub const fn new() -> Self {
        Self { attempted: false }
    }
    pub fn wait(&mut self, device: &mut dyn Device) -> bool {
        self.attempted = true;
        wait(device)
    }
    #[cfg(feature = "pass")]
    pub fn take(&mut self) -> bool {
        core::mem::take(&mut self.attempted)
    }
}

#[cfg(all(test, feature = "pass", any(feature = "oath", feature = "openpgp")))]
mod tests {
    use super::*;
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
