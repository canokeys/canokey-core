// SPDX-License-Identifier: Apache-2.0
pub trait Device {
    fn serial(&mut self, output: &mut [u8; 4]);
    /// Raw firmware version (0), product (1), core revision (2), or chip ID (3).
    /// The caller owns protocol validation and response truncation.
    fn information(&mut self, kind: u8, output: &mut [u8]) -> usize {
        let data: &[u8] = if kind == 3 { &[0; 13] } else { b"unknown" };
        let len = output.len().min(data.len());
        output[..len].copy_from_slice(&data[..len]);
        len
    }
    /// Hardware bootloader handoff word, if this board supports recovery.
    fn recovery_word(&mut self) -> Option<u32> {
        None
    }
    fn now(&mut self) -> u32;
    fn touched(&mut self) -> bool;
    /// Active contactless mode supplies presence without a touch sensor.
    fn contactless(&mut self) -> bool {
        false
    }
    /// Publish settings to disjoint device/IRQ state; must not reenter Core.
    fn configuration_changed(&mut self, _flags: u32) {}
    fn led_idle(&mut self) {
        self.led(false);
    }
    fn wink(&mut self) {}
    /// Consume a completed, unexpired gesture for CTAP1 polling.
    fn poll_presence(&mut self) -> bool {
        false
    }
    /// Transport-only progress; false means reset/disconnect/cancel.
    fn progress(&mut self) -> bool;
    /// Transport-only status: true while waiting for user presence, false while processing.
    fn keepalive(&mut self, _waiting: bool) {}
    fn led(&mut self, on: bool);
}

#[cfg(feature = "ctap")]
const POLL_LATCH_MS: u32 = 1_000;
#[cfg(feature = "ctap")]
const WINK_MS: u32 = 1_000;
#[cfg(feature = "ctap")]
const PROMPT_MS: u32 = 2_000;
#[cfg(feature = "ctap")]
const WINK_INTERVAL_MS: u32 = 50;
#[cfg(feature = "ctap")]
const PROMPT_INTERVAL_MS: u32 = 100;

/// CTAP1 polling observes completed gestures between commands. The latch has
/// the same one-second lifetime as the C touch driver and is consumed once.
#[cfg(feature = "ctap")]
pub struct Polling {
    // Polling is a nonblocking CTAP1 latch; it intentionally does not share
    // the blocking waiter's timing state or strong factory-reset sequence.
    armed: bool,
    pressed: bool,
    released: Option<u32>,
    prompt: Option<(u32, bool)>,
}
#[cfg(feature = "ctap")]
impl Polling {
    pub const fn new() -> Self {
        Self {
            armed: false,
            pressed: false,
            released: None,
            prompt: None,
        }
    }
    pub fn sample(&mut self, pressed: bool, now: u32) -> Option<bool> {
        if self.armed && self.pressed && !pressed {
            self.released = Some(now);
        }
        self.armed |= !pressed;
        self.pressed = pressed;
        if self
            .released
            .is_some_and(|t| now.wrapping_sub(t) >= POLL_LATCH_MS)
        {
            self.released = None;
        }
        self.prompt.map(|(start, wink)| {
            let elapsed = now.wrapping_sub(start);
            let duration = if wink { WINK_MS } else { PROMPT_MS };
            let interval = if wink {
                WINK_INTERVAL_MS
            } else {
                PROMPT_INTERVAL_MS
            };
            if elapsed >= duration {
                self.prompt = None;
            }
            elapsed < duration && (elapsed / interval).is_multiple_of(2)
        })
    }
    pub fn take(&mut self, now: u32) -> bool {
        if self
            .released
            .take()
            .is_some_and(|t| now.wrapping_sub(t) < POLL_LATCH_MS)
        {
            self.prompt = None;
            true
        } else {
            self.prompt.get_or_insert((now, false));
            false
        }
    }
    pub fn prompt_active(&self) -> bool {
        self.prompt.is_some()
    }
    pub fn wink(&mut self, now: u32) {
        self.prompt = Some((now, true));
    }
    pub fn clear(&mut self) {
        self.released = None;
        self.prompt = None;
        self.armed = false;
        self.pressed = false;
    }
}
