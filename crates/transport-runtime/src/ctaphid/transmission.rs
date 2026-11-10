// SPDX-License-Identifier: Apache-2.0
//! Logical IN stall deadline, independent of controller buffer ownership.

/// CanoKey abandons a request after 1000 ms without IN completion. Expiry
/// releases logical request state only: the facade must preserve the submitted
/// report until completion or hardware reset releases the endpoint pointer.
#[repr(transparent)]
pub struct TransmissionDeadline {
    sent_at: u32,
}
impl TransmissionDeadline {
    pub const TIMEOUT_MS: u32 = 1000;

    pub const fn new() -> Self {
        Self { sent_at: 0 }
    }

    /// Publish only after a successful submission, using its completion tick.
    pub fn sent(&mut self, now: u32) {
        self.sent_at = now;
    }

    /// The facade owns the pending flag. Execution-end draining also uses this
    /// elapsed-time check when IN was already busy before execution began.
    pub fn expired(&self, now: u32) -> bool {
        now.wrapping_sub(self.sent_at) >= Self::TIMEOUT_MS
    }
}
impl Default for TransmissionDeadline {
    fn default() -> Self {
        Self::new()
    }
}
