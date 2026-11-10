// SPDX-License-Identifier: Apache-2.0
//! Class admission follows serialized cleanup of the current USB generation.

/// IRQs advance the global mailbox generation on bus/configuration reset.
/// The main loop captures it before cleanup and acknowledges it afterwards.
/// Callers serialize each check/publication with their USB IRQ lock; cleanup
/// itself must run outside that lock and outside any application borrow.
#[repr(transparent)]
pub struct Lifecycle {
    serviced: u32,
}
impl Lifecycle {
    pub const fn new() -> Self {
        Self { serviced: 0 }
    }

    pub fn ready(&self, configured: bool, current: u32) -> bool {
        configured && self.serviced == current
    }

    /// None rejects interrupted cleanup. Some(true) reopens class reception
    /// once; Some(false) means this generation was already serviced.
    pub fn complete(&mut self, captured: u32, current: u32) -> Option<bool> {
        if captured != current {
            return None;
        }
        let changed = self.serviced != captured;
        self.serviced = captured;
        Some(changed)
    }
}
impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}
