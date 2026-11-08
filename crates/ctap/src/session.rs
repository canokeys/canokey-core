// SPDX-License-Identifier: Apache-2.0
//! Continuation ownership and idle time; products own cursors and their cleanup.

/// CTAP continuation inactivity window, in milliseconds.
pub const CONTINUATION_IDLE_MS: u32 = 30_000;

/// Products retain their established acceptance of the exact timeout instant.
#[derive(Clone, Copy)]
pub enum Boundary {
    AtLimit,
    AfterLimit,
}

/// Non-sensitive metadata only. Binding may be a channel/generation pair or `()`
/// when the product already resets the enclosing session on connection changes.
/// Checking does not refresh time or clear a credential cursor: callers refresh
/// at their own admission/signing point and erase secrets on rejection/reset.
pub struct IdleWindow<Binding> {
    binding: Binding,
    refreshed: u32,
}

impl<Binding> IdleWindow<Binding> {
    pub const fn new(binding: Binding) -> Self {
        Self {
            binding,
            refreshed: 0,
        }
    }

    pub fn refresh(&mut self, binding: Binding, now: u32) {
        self.binding = binding;
        self.refreshed = now;
    }
}

impl<Binding: PartialEq> IdleWindow<Binding> {
    pub fn accepts(&self, binding: &Binding, now: u32, boundary: Boundary) -> bool {
        if self.binding != *binding {
            return false;
        }
        let elapsed = now.wrapping_sub(self.refreshed);
        match boundary {
            Boundary::AtLimit => elapsed < CONTINUATION_IDLE_MS,
            Boundary::AfterLimit => elapsed <= CONTINUATION_IDLE_MS,
        }
    }
}
