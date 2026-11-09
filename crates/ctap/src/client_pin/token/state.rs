// SPDX-License-Identifier: Apache-2.0
//! Sole token backing and metadata, shared by standard and product permissions.
use super::super::KEY_BYTES;
use super::{Error, MissingRp, Scope};

// Private token followed by public SHA-256 RP binding. This is volatile owner
// storage, not a wire/record layout. Contiguity permits one complete erasure.
const RP_OFFSET: usize = KEY_BYTES;
const MATERIAL_BYTES: usize = KEY_BYTES + KEY_BYTES;

/// No Clone/Copy/Debug or raw-secret getter. Synchronous crypto loans cannot
/// return a borrowed token. The outer owner must clear on failed publication,
/// reset and expiry; a product with automatic erasure calls clear from Drop.
/// Permission width reflects the actual wire field or native extension bits.
pub struct Token<Permissions = u16> {
    material: [u8; MATERIAL_BYTES],
    pub permissions: Permissions,
    pub issued: u32,
    pub last_used: u32,
    rp_bound: bool,
}
impl<P: Copy> Token<P> {
    pub const fn empty(no_permissions: P) -> Self {
        Self::new(no_permissions, 0)
    }
    pub const fn new(permissions: P, now: u32) -> Self {
        Self {
            material: [0x00; MATERIAL_BYTES],
            permissions,
            issued: now,
            last_used: now,
            rp_bound: false,
        }
    }
    /// Issuance fixes both clock origins; re-agreement must never call this.
    /// The caller publishes the complete grant only after crypto/IO succeeds.
    pub fn start(&mut self, permissions: P, now: u32) {
        self.permissions = permissions;
        self.issued = now;
        self.last_used = now;
    }
    pub fn mark_used(&mut self, now: u32) {
        self.last_used = now;
    }
    pub fn remaining_ms(&self, now: u32) -> Option<u32> {
        super::lifetime_remaining(now, self.issued, self.last_used)
    }
    pub fn rp_id(&self) -> Option<&[u8; KEY_BYTES]> {
        self.rp_bound
            .then(|| (&self.material[RP_OFFSET..]).try_into().unwrap())
    }
    pub fn bind_rp(&mut self, rp: Option<[u8; KEY_BYTES]>) {
        if let Some(rp) = rp {
            self.material[RP_OFFSET..].copy_from_slice(&rp);
            self.rp_bound = true;
        } else {
            self.material[RP_OFFSET..].fill(0x00);
            self.rp_bound = false;
        }
    }
    /// Hash directly into the sole RP backing. Failed partial output remains
    /// unbound and the caller's failure teardown must wipe the complete owner.
    pub fn prepare_rp<E>(
        &mut self,
        hash: impl FnOnce(&mut [u8; KEY_BYTES]) -> Result<(), E>,
    ) -> Result<(), E> {
        let result = hash((&mut self.material[RP_OFFSET..]).try_into().unwrap());
        self.rp_bound = result.is_ok();
        result
    }
    /// A primitive may consume a secret synchronously, but cannot export its loan.
    ///
    /// ```compile_fail
    /// use canokey_ctap::client_pin::token::Token;
    /// let owner = Token::empty(0x00u8);
    /// let escaped = owner.with_secret(|secret| secret);
    /// assert_eq!(escaped.len(), 32);
    /// ```
    pub fn with_secret<T>(&self, crypto: impl FnOnce(&[u8; KEY_BYTES]) -> T) -> T {
        crypto((&self.material[..KEY_BYTES]).try_into().unwrap())
    }
    /// A failed RNG/primitive can have partially filled the backing. The caller
    /// must clear the complete owner before returning that failure externally.
    pub fn with_secret_mut<T>(&mut self, crypto: impl FnOnce(&mut [u8; KEY_BYTES]) -> T) -> T {
        crypto((&mut self.material[..KEY_BYTES]).try_into().unwrap())
    }
}

impl<P: Copy + From<u8>> Token<P> {
    #[inline(always)]
    pub fn clear(&mut self, mut wipe: impl FnMut(&mut [u8])) {
        wipe(&mut self.material);
        self.rp_bound = false;
        self.permissions = P::from(0x00);
        self.issued = 0;
        self.last_used = 0;
    }
}
impl<P: Copy + Into<u16>> Token<P> {
    /// Shared scope/MAC admission does not commit use or RP binding. Deferred
    /// record-RP admission must finish before the caller marks successful use.
    pub fn authorize<E>(
        &self,
        required: u16,
        rp: Option<&[u8; KEY_BYTES]>,
        missing_rp: MissingRp,
        verify: impl FnOnce(&[u8; KEY_BYTES]) -> Result<(), E>,
        equal: impl FnOnce(&[u8], &[u8]) -> bool,
    ) -> Result<(), Error<E>> {
        super::authorize(
            Scope {
                granted: self.permissions.into(),
                required,
                bound_rp: self.rp_id(),
                requested_rp: rp,
                missing_rp,
            },
            || self.with_secret(verify),
            equal,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_erases_both_backings_and_authority_after_partial_primitives() {
        let mut owner = Token::new(0x0101u16, 123);
        owner.bind_rp(Some([0x51; KEY_BYTES]));
        owner.mark_used(124);
        let result = owner.with_secret_mut(|secret| {
            secret[..7].fill(0xa5);
            Err::<(), _>(())
        });
        assert!(result.is_err());
        let result = owner.prepare_rp(|rp| {
            rp[..5].fill(0xb6);
            Err::<(), _>(())
        });
        assert!(result.is_err());
        assert!(owner.rp_id().is_none());
        assert!(owner.material.iter().any(|byte| *byte != 0x00));
        let mut wipes = 0;
        owner.clear(|bytes| {
            wipes += 1;
            assert_eq!(bytes.len(), MATERIAL_BYTES);
            assert_eq!(&bytes[..7], &[0xa5; 7]);
            assert_eq!(&bytes[RP_OFFSET..RP_OFFSET + 5], &[0xb6; 5]);
            bytes.fill(0x00);
        });
        assert_eq!(wipes, 1);
        assert_eq!(owner.material, [0x00; MATERIAL_BYTES]);
        assert_eq!(owner.permissions, 0x0000);
        assert_eq!((owner.issued, owner.last_used), (0, 0));
        assert!(owner.rp_id().is_none());
    }

    fn admission_does_not_commit<P: Copy + Into<u16>>(permissions: P) {
        let rp = [0x51; KEY_BYTES];
        let mut owner = Token::new(permissions, 123);
        owner.with_secret_mut(|secret| secret.fill(0xa5));
        for required in [0x0001, 0x0003, 0x0100] {
            for valid_mac in [false, true] {
                let mut verified = false;
                let result = owner.authorize(
                    required,
                    Some(&rp),
                    MissingRp::Deny,
                    |secret| {
                        verified = true;
                        assert_eq!(secret, &[0xa5; KEY_BYTES]);
                        if !valid_mac {
                            return Err(());
                        }
                        Ok(())
                    },
                    |bound, requested| bound == requested,
                );
                let scope_allowed = permissions.into() & required == required;
                assert_eq!(verified, scope_allowed);
                assert_eq!(result.is_ok(), scope_allowed && valid_mac);
                assert_eq!((owner.issued, owner.last_used), (123, 123));
                assert!(owner.rp_id().is_none());
            }
        }
        // A successful MAC alone cannot commit deferred credential-RP admission.
        owner.bind_rp(Some(rp));
        assert_eq!(
            owner.authorize(
                0x0001,
                None,
                MissingRp::Allow,
                |_| Ok::<_, ()>(()),
                |a, b| a == b
            ),
            Ok(())
        );
        assert_eq!(owner.last_used, 123);
        assert_eq!(owner.rp_id(), Some(&rp));
        assert_eq!(
            owner.authorize(
                0x0001,
                Some(&[0x52; KEY_BYTES]),
                MissingRp::Deny,
                |_| panic!("scope must precede MAC"),
                |a, b| a == b
            ),
            Err(Error::<()>::Scope)
        );
        owner.mark_used(124);
        assert_eq!((owner.issued, owner.last_used), (123, 124));
    }

    #[test]
    fn narrow_and_native_permission_owners_share_admission_and_commit_rules() {
        admission_does_not_commit(0x01u8);
        admission_does_not_commit(0x0101u16);
    }

    #[test]
    fn use_refreshes_only_idle_clock_across_wrap_and_restart_fixes_both_origins() {
        for origin in [0, u32::MAX - 1000] {
            let mut owner = Token::empty(0x00u8);
            owner.start(0x01, origin);
            assert_eq!(owner.remaining_ms(origin.wrapping_add(29_999)), Some(1));
            assert_eq!(owner.remaining_ms(origin.wrapping_add(30_000)), None);
            owner.mark_used(origin.wrapping_add(590_000));
            assert_eq!(owner.remaining_ms(origin.wrapping_add(599_999)), Some(1));
            assert_eq!(owner.remaining_ms(origin.wrapping_add(600_000)), None);
            assert_eq!(owner.issued, origin);
            owner.start(0x02, origin.wrapping_add(600_001));
            assert_eq!(
                (owner.issued, owner.last_used),
                (origin.wrapping_add(600_001), origin.wrapping_add(600_001))
            );
        }
    }
}
