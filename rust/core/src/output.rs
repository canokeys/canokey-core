// SPDX-License-Identifier: Apache-2.0
//! Rust owns gesture interpretation and the lifetime of a password output job.
#![forbid(unsafe_code)]
use crate::{Platform, registry::Registry};
pub struct Output {
    bytes: [u8; 33],
    used: usize,
    position: usize,
    contact: bool,
    since: u32,
    boot_ready: bool,
    suppressed: bool,
    draining: bool,
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
        }
    }
    pub fn inhibit(&mut self, pressed: bool, p: &mut dyn Platform) {
        self.reset(p);
        self.suppressed = pressed;
    }
    pub fn busy(&self) -> bool {
        self.used != 0 || self.draining
    }
    pub fn reset(&mut self, p: &mut dyn Platform) {
        p.wipe(&mut self.bytes);
        self.used = 0;
        self.position = 0;
        self.contact = false;
        self.draining = false;
    }
    pub fn sample(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        registry: &Registry,
        p: &mut dyn Platform,
    ) -> Option<u8> {
        if ready {
            self.draining = false;
        }
        if self.suppressed {
            self.suppressed = pressed;
            return None;
        }
        if !self.boot_ready {
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
        if !pressed && self.contact && !self.busy() {
            let elapsed = now.wrapping_sub(self.since);
            if elapsed >= 30 {
                self.used = registry
                    .touch(u8::from(elapsed >= 500), &mut self.bytes, p)
                    .unwrap_or(0);
                self.position = 0;
            }
        }
        self.contact = pressed;
        if !ready || self.used == 0 {
            return None;
        }
        self.draining = true;
        let byte = self.bytes[self.position];
        p.wipe(&mut self.bytes[self.position..self.position + 1]);
        self.position += 1;
        if self.position == self.used {
            self.used = 0;
            self.position = 0;
        }
        Some(byte)
    }
}
