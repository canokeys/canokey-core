// SPDX-License-Identifier: Apache-2.0
//! Sole connection-owned PIN material; power-cycle allowance has a longer life.
use super::{KEY_BYTES, token};

/// One standard PIN session owns agreement and token material. Product identity,
/// public-key cache and native token metadata may view it but cannot copy secrets.
/// Volatile retry allowance lives in retry::Attempts outside this connection
/// owner: CID/slot/session reset must not refund a power-cycle lockout.
// Keep readiness and token metadata at small offsets for Thumb-1 access.
// This volatile layout is not a wire format, record format or exported C ABI.
#[repr(C)]
pub struct Session<Permissions = u16> {
    agreement_ready: bool,
    pub(crate) token: token::Token<Permissions>,
    private: [u8; KEY_BYTES],
}
impl<P: Copy> Session<P> {
    pub const fn empty(no_permissions: P) -> Self {
        Self {
            token: token::Token::empty(no_permissions),
            private: [0x00; KEY_BYTES],
            agreement_ready: false,
        }
    }
    /// Read-only view of the session-owned token; callers cannot replace it or
    /// bypass issuance clocks by assigning metadata.
    ///
    /// ```compile_fail
    /// use canokey_ctap::client_pin::{Session, token::Token};
    /// let mut session = Session::empty(0x00u8);
    /// session.token = Token::empty(0x00);
    /// ```
    #[inline]
    pub fn token(&self) -> &token::Token<P> {
        &self.token
    }
    #[inline]
    pub fn start_token(&mut self, permissions: P, now: u32) {
        self.token.start(permissions, now);
    }
    #[inline]
    pub fn mark_token_used(&mut self, now: u32) {
        self.token.mark_used(now);
    }
    #[inline]
    pub fn retain_token_permissions(&mut self, permissions: P)
    where
        P: core::ops::BitAnd<Output = P>,
    {
        self.token.retain_permissions(permissions);
    }
    #[inline]
    pub fn bind_token_rp(&mut self, rp: Option<[u8; KEY_BYTES]>) {
        self.token.bind_rp(rp);
    }
    #[inline]
    pub fn prepare_token_rp<E>(
        &mut self,
        hash: impl FnOnce(&mut [u8; KEY_BYTES]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.token.prepare_rp(hash)
    }
    #[inline]
    pub fn with_token_secret_mut<T>(
        &mut self,
        primitive: impl FnOnce(&mut [u8; KEY_BYTES]) -> T,
    ) -> T {
        self.token.with_secret_mut(primitive)
    }
    pub fn agreement_ready(&self) -> bool {
        self.agreement_ready
    }
    /// The adapter has validated the candidate and completed its required public
    /// metadata. Public export can remain a separate fallible operation.
    pub fn commit_agreement(&mut self) {
        self.agreement_ready = true;
    }
    /// Private-key loans cannot escape the synchronous primitive call.
    ///
    /// ```compile_fail
    /// use canokey_ctap::client_pin::Session;
    /// let owner = Session::empty(0x00u8);
    /// let escaped = owner.with_private(|private| private);
    /// assert_eq!(escaped.len(), 32);
    /// ```
    pub fn with_private<T>(&self, primitive: impl FnOnce(&[u8; KEY_BYTES]) -> T) -> T {
        primitive(&self.private)
    }
    pub fn with_private_mut<T>(&mut self, primitive: impl FnOnce(&mut [u8; KEY_BYTES]) -> T) -> T {
        // A partial or failed overwrite is no longer an established agreement.
        self.agreement_ready = false;
        primitive(&mut self.private)
    }
    pub fn clear_agreement(&mut self, wipe: impl FnOnce(&mut [u8])) {
        self.agreement_ready = false;
        wipe(&mut self.private);
    }
}
impl<P: Copy + From<u8>> Session<P> {
    #[inline]
    pub fn clear_token(&mut self, wipe: impl FnMut(&mut [u8])) {
        self.token.clear(wipe);
    }
    pub fn clear(&mut self, mut wipe: impl FnMut(&mut [u8])) {
        self.clear_agreement(&mut wipe);
        self.token.clear(wipe);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_pin::retry::{Attempts, POWER_CYCLE_ATTEMPTS, Rejection};

    #[test]
    fn complete_owner_clear_erases_partial_candidate_and_live_token_without_refunding_attempts() {
        let mut owner = Session::empty(0x00u16);
        let mut attempts = Attempts::new();
        for _ in 0..POWER_CYCLE_ATTEMPTS {
            attempts.rejected(7);
        }
        owner.token.with_secret_mut(|secret| secret.fill(0x61));
        owner.token.start(0x0101, 123);
        owner.token.bind_rp(Some([0x52; KEY_BYTES]));
        owner.token.mark_used(124);
        owner.with_private_mut(|private| private.fill(0x73));
        owner.commit_agreement();
        let result = owner.with_private_mut(|private| {
            private[..7].fill(0x84);
            Err::<(), _>(())
        });
        assert!(result.is_err());
        assert!(!owner.agreement_ready());
        let mut lengths = [0; 2];
        let mut wipes = 0;
        owner.clear(|bytes| {
            lengths[wipes] = bytes.len();
            wipes += 1;
            bytes.fill(0x00);
        });
        assert_eq!(lengths, [KEY_BYTES, 2 * KEY_BYTES]);
        assert!(!owner.agreement_ready());
        assert_eq!(owner.private, [0x00; KEY_BYTES]);
        assert_eq!(owner.token.with_secret(|secret| *secret), [0x00; KEY_BYTES]);
        assert_eq!(owner.token.permissions, 0x0000);
        assert_eq!((owner.token.issued, owner.token.last_used), (0, 0));
        assert!(owner.token.rp_id().is_none());
        assert!(attempts.blocked());
        attempts.reset();
        assert_eq!(attempts.remaining(), POWER_CYCLE_ATTEMPTS);
    }

    #[test]
    fn agreement_loss_and_regeneration_never_change_existing_token_scope_or_clocks() {
        let mut owner = Session::empty(0x00u8);
        owner.token.with_secret_mut(|secret| secret.fill(0x61));
        owner.token.start(0x01, 123);
        owner.token.mark_used(124);
        owner.token.bind_rp(Some([0x52; KEY_BYTES]));
        owner.with_private_mut(|private| private.fill(0x73));
        owner.commit_agreement();
        owner.clear_agreement(|bytes| bytes.fill(0x00));
        assert!(!owner.agreement_ready());
        assert_eq!(owner.private, [0x00; KEY_BYTES]);
        owner.with_private_mut(|private| private.fill(0x84));
        assert!(!owner.agreement_ready());
        owner.commit_agreement();
        assert!(owner.agreement_ready());
        assert_eq!(owner.token.with_secret(|secret| *secret), [0x61; KEY_BYTES]);
        assert_eq!(owner.token.permissions, 0x01);
        assert_eq!((owner.token.issued, owner.token.last_used), (123, 124));
        assert_eq!(owner.token.rp_id(), Some(&[0x52; KEY_BYTES]));
    }

    #[test]
    fn token_scope_changes_and_revocation_preserve_the_live_agreement() {
        let mut owner = Session::empty(0x00u8);
        owner.with_private_mut(|private| private.fill(0x73));
        owner.commit_agreement();
        owner.token.bind_rp(Some([0x52; KEY_BYTES]));
        assert!(owner.agreement_ready());
        owner
            .token
            .prepare_rp(|rp| {
                rp[..7].fill(0x84);
                Err::<(), _>(())
            })
            .unwrap_err();
        assert!(owner.agreement_ready());
        assert!(owner.token.rp_id().is_none());
        owner.token.clear(|bytes| bytes.fill(0x00));
        assert!(owner.agreement_ready());
        assert_eq!(owner.private, [0x73; KEY_BYTES]);
        owner.token.bind_rp(Some([0x52; KEY_BYTES]));
        owner.clear_agreement(|bytes| bytes.fill(0x00));
        assert!(!owner.agreement_ready());
        assert_eq!(owner.token.rp_id(), Some(&[0x52; KEY_BYTES]));
    }

    #[test]
    fn moving_or_replacing_tokens_cannot_move_agreement_readiness() {
        let mut established = Session::empty(0x00u8);
        established.with_private_mut(|private| private.fill(0x73));
        established.commit_agreement();
        let mut empty = Session::empty(0x00u8);
        core::mem::swap(&mut established.token, &mut empty.token);
        assert!(established.agreement_ready());
        assert!(!empty.agreement_ready());
        assert_eq!(
            established.with_private(|private| *private),
            [0x73; KEY_BYTES]
        );
        assert_eq!(empty.with_private(|private| *private), [0x00; KEY_BYTES]);
        established.with_private_mut(|private| private.fill(0x74));
        assert!(!established.agreement_ready());
        established.commit_agreement();
        established.token = token::Token::empty(0x00);
        established.token.clear(|bytes| bytes.fill(0x00));
        assert!(established.agreement_ready());
        established.clear_agreement(|bytes| bytes.fill(0x00));
        assert!(!established.agreement_ready());
    }

    #[test]
    fn power_cycle_counter_saturates_and_durable_exhaustion_has_precedence() {
        for durable in 0..=8 {
            let mut attempts = Attempts::new();
            for failures in 1..=5 {
                let result = attempts.rejected(durable);
                let remaining = POWER_CYCLE_ATTEMPTS.saturating_sub(failures);
                assert_eq!(attempts.remaining(), remaining);
                assert_eq!(attempts.blocked(), remaining == 0);
                let expected = if durable == 0 {
                    Rejection::Blocked
                } else if remaining == 0 {
                    Rejection::PowerCycleBlocked
                } else {
                    Rejection::Invalid
                };
                assert_eq!(result, expected);
            }
        }
    }
}
