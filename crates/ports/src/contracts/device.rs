// SPDX-License-Identifier: Apache-2.0
// CIU board ABI writes the complete 13-byte chip identifier.
pub const CHIP_ID_BYTES: usize = 13;
/// Stable kinds passed to the board-information C ABI and ADMIN read command.
pub mod board_info_kind {
    pub const FIRMWARE: u8 = 0x00;
    pub const PRODUCT: u8 = 0x01;
    pub const CORE: u8 = 0x02;
    pub const CHIP_ID: u8 = 0x03;
}
pub trait Device {
    /// Write the device serial. Native bindings without `platform-serial` leave
    /// output unchanged; callers must initialize any fallback before the call.
    fn serial(&mut self, output: &mut [u8; 4]);
    /// Raw firmware version (0), product (1), core revision (2), or chip ID (3).
    /// The caller owns protocol validation and response truncation.
    fn information(&mut self, kind: u8, output: &mut [u8]) -> usize {
        let data: &[u8] = if kind == board_info_kind::CHIP_ID {
            &[0; CHIP_ID_BYTES]
        } else {
            b"unknown"
        };
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

#[cfg(feature = "ctap")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Idle,
    Presence,
    Wink,
}

/// CTAP1 polling observes completed gestures between commands. The latch has
/// the same one-second lifetime as the C touch driver and is consumed once.
#[cfg(feature = "ctap")]
pub struct Polling {
    // Polling is a nonblocking CTAP1 latch; it intentionally does not share
    // the blocking waiter's timing state or strong factory-reset sequence.
    armed: bool,
    pressed: bool,
    // Explicit validity keeps idle state zero-initialized and avoids timestamp padding.
    released_at: u32,
    prompt_at: u32,
    release_pending: bool,
    prompt: Prompt,
}
#[cfg(feature = "ctap")]
impl Polling {
    pub const fn new() -> Self {
        Self {
            armed: false,
            pressed: false,
            released_at: 0,
            prompt_at: 0,
            release_pending: false,
            prompt: Prompt::Idle,
        }
    }
    pub fn sample(&mut self, pressed: bool, now: u32) -> Option<bool> {
        if self.armed && self.pressed && !pressed {
            self.released_at = now;
            self.release_pending = true;
        }
        self.armed |= !pressed;
        self.pressed = pressed;
        if self.release_pending && now.wrapping_sub(self.released_at) >= POLL_LATCH_MS {
            self.release_pending = false;
        }
        if self.prompt == Prompt::Idle {
            None
        } else {
            let elapsed = now.wrapping_sub(self.prompt_at);
            let wink = self.prompt == Prompt::Wink;
            let duration = if wink { WINK_MS } else { PROMPT_MS };
            let interval = if wink {
                WINK_INTERVAL_MS
            } else {
                PROMPT_INTERVAL_MS
            };
            if elapsed >= duration {
                self.prompt = Prompt::Idle;
            }
            Some(elapsed < duration && (elapsed / interval).is_multiple_of(2))
        }
    }
    pub fn take(&mut self, now: u32) -> bool {
        let accepted = self.release_pending && now.wrapping_sub(self.released_at) < POLL_LATCH_MS;
        self.release_pending = false;
        if accepted {
            self.prompt = Prompt::Idle;
            true
        } else {
            if self.prompt == Prompt::Idle {
                self.prompt_at = now;
                self.prompt = Prompt::Presence;
            }
            false
        }
    }
    pub fn prompt_active(&self) -> bool {
        self.prompt != Prompt::Idle
    }
    pub fn wink(&mut self, now: u32) {
        self.prompt_at = now;
        self.prompt = Prompt::Wink;
    }
    pub fn clear(&mut self) {
        self.release_pending = false;
        self.prompt = Prompt::Idle;
        self.armed = false;
        self.pressed = false;
    }
}
