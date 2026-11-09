// SPDX-License-Identifier: Apache-2.0
//! Standard error disposition and continuation metadata; owners erase state.

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

/// A standard internal failure can mean a primitive or uncertain persistent
/// commit changed state. Revoke the complete authorization session then. Ordinary
/// request/authentication/presence rejections retain agreement and any token not
/// already expired or consumed. Cursor/output failure cleanup remains mandatory.
/// Product-only integrity/storage errors must map to Internal or reset in their
/// adapter; this rule does not replace transport-generation invalidation.
#[inline]
pub const fn reset_on_error(status: u8) -> bool {
    status == crate::status::Status::Internal as u8
}
