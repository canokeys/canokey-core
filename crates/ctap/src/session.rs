// SPDX-License-Identifier: Apache-2.0
//! Standard error disposition and continuation metadata; owners erase state.

/// CTAP continuation inactivity window, in milliseconds.
pub const CONTINUATION_IDLE_MS: u32 = 30_000;

// CTAP PIN/UV permissions occupy one byte. Product context-bound grants live
// outside this field and cannot survive loss of their agreement identity.
const STANDARD_PERMISSION_MASK: u16 = 0x00ff;

/// Loans the sole PIN owner without exporting its key or token. Erasure must
/// clear private agreement material and any product identity derived from it.
/// Retention changes permissions only: token bytes, RP and clocks stay intact.
pub trait PinAgreement {
    fn erase_agreement(&mut self);
    fn permissions(&self) -> u16;
    fn retain_permissions(&mut self, permissions: u16);
}

/// A compared PIN mismatch invalidates agreement, retaining standard grants.
/// Early blocked admission must not call this transition. Products also use it
/// before replacing an agreement-bound native context; it never refreshes use.
#[inline]
pub fn lose_pin_agreement(owner: &mut impl PinAgreement) {
    owner.erase_agreement();
    owner.retain_permissions(owner.permissions() & STANDARD_PERMISSION_MASK);
}

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
