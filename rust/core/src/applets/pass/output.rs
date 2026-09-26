// SPDX-License-Identifier: Apache-2.0
//! Rust owns gesture interpretation and the lifetime of a password output job.
#![forbid(unsafe_code)]
#[cfg(test)]
use crate::ports::Memory;
pub struct Output {
    // Up to 32 password bytes plus an optional Enter character.
    bytes: [u8; 33],
    used: usize,
    position: usize,
    contact: bool,
    since: u32,
    boot_ready: bool,
    // Another operation claimed this contact; wait for release before rearming.
    suppressed: bool,
    // Last byte has left this buffer but the keyboard transport is still busy.
    draining: bool,
    // One completed gesture may wait behind the active text and key release.
    // Like the legacy touch latch, a later gesture replaces the pending one.
    pending: u8,
}
impl Output {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 33],
            used: 0,
            position: 0,
            contact: false,
            since: 0,
            boot_ready: false,
            suppressed: false,
            draining: false,
            pending: 0,
        }
    }
    pub fn inhibit(&mut self, pressed: bool, memory: &crate::ports::MemoryPort<'_>) {
        self.reset(memory);
        self.suppressed = pressed;
    }
    /// Replace queued text; the transport completes any prior key release.
    pub fn eject(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        self.reset(memory);
        self.suppressed = false;
        self.bytes[0] = 3;
        self.used = 1;
    }
    pub fn busy(&self) -> bool {
        self.used != 0 || self.draining || self.pending != 0
    }
    pub fn reset(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.bytes);
        self.used = 0;
        self.position = 0;
        self.contact = false;
        self.draining = false;
        self.pending = 0;
    }
    pub fn sample(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        memory: &crate::ports::MemoryPort<'_>,
        mut resolve: impl FnMut(u8, &mut [u8]) -> usize,
    ) -> Option<u8> {
        if ready {
            self.draining = false;
        }
        if self.suppressed {
            self.suppressed = pressed;
            if pressed {
                return None;
            }
            self.contact = false;
        }
        if !self.boot_ready && self.used == 0 {
            if now <= 1500 {
                self.contact = false;
                return None;
            }
            // Do not accept a contact that began in the startup ignore window.
            if pressed {
                return None;
            }
            self.boot_ready = true;
        }
        if pressed && !self.contact {
            self.since = now;
        }
        if !pressed && self.contact {
            let elapsed = now.wrapping_sub(self.since);
            // Milliseconds: reject contact bounce below 30; a hold of at least
            // 500 selects slot 1, otherwise the short-touch slot 0.
            if elapsed >= 30 {
                self.pending = 1 + u8::from(elapsed >= 500);
            }
        }
        self.contact = pressed;
        if self.pending != 0 && self.used == 0 && !self.draining {
            let slot = self.pending - 1;
            self.pending = 0;
            self.used = resolve(slot, &mut self.bytes).min(self.bytes.len());
            self.position = 0;
        }
        if !ready || self.used == 0 {
            return None;
        }
        self.draining = true;
        let byte = self.bytes[self.position];
        memory.wipe(&mut self.bytes[self.position..self.position + 1]);
        self.position += 1;
        if self.position == self.used {
            self.used = 0;
            self.position = 0;
        }
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Erase;
    impl Memory for Erase {
        fn wipe(&self, b: &mut [u8]) {
            b.fill(0);
        }
    }
    #[test]
    fn claimed_gesture_is_not_replayed_after_wait() {
        let mut output = Output::new();
        let mut calls = 0;
        let mut resolve = |_: u8, b: &mut [u8]| {
            calls += 1;
            b[0] = b'x';
            1
        };
        assert_eq!(output.sample(false, 1600, true, &Erase, &mut resolve), None);
        assert_eq!(output.sample(true, 2000, true, &Erase, &mut resolve), None);
        // A presence request timed out while the contact was still held.
        output.inhibit(true, &Erase);
        assert_eq!(output.sample(true, 32000, true, &Erase, &mut resolve), None);
        assert_eq!(
            output.sample(false, 32100, true, &Erase, &mut resolve),
            None
        );
        // Only a subsequent independent gesture is eligible for PASS.
        assert_eq!(output.sample(true, 33000, true, &Erase, &mut resolve), None);
        assert_eq!(
            output.sample(false, 33100, true, &Erase, &mut resolve),
            Some(b'x')
        );
        assert_eq!(calls, 1);
    }
}
