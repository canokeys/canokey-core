// SPDX-License-Identifier: Apache-2.0
//! Durable charge-before-compare sequencing; products own records and grants.

pub const MAX_RETRIES: u8 = 8;
pub const POWER_CYCLE_ATTEMPTS: u8 = 3;

/// The adapter updates its existing record before persisting the charge. A
/// persistence error may already be durable; it must fail closed without a
/// comparison, refund or grant. Comparison may decrypt into owner-held scratch.
/// Rejection owns power-cycle charging and agreement/session invalidation.
/// A correct verifier restores volatile attempts and persists the refund before
/// any subsequent new-PIN policy, record replacement or grant publication. A
/// failed refund is uncertain and must not authorize those later operations.
pub trait Verification {
    type Error;
    fn remaining(&self) -> u8;
    fn blocked(&self) -> Self::Error;
    fn charge(&mut self, remaining: u8) -> Result<(), Self::Error>;
    fn compare(&mut self) -> Result<bool, Self::Error>;
    fn rejected(&mut self) -> Self::Error;
    fn accepted(&mut self) -> Result<(), Self::Error>;
}

#[inline]
pub fn verify<V: Verification>(backend: &mut V) -> Result<(), V::Error> {
    let Some(remaining) = backend.remaining().checked_sub(1) else {
        return Err(backend.blocked());
    };
    backend.charge(remaining)?;
    if backend.compare()? {
        backend.accepted()
    } else {
        Err(backend.rejected())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Blocked,
    PowerCycleBlocked,
    Invalid,
}
/// Durable exhaustion takes precedence over the power-cycle attempt limit.
#[inline]
pub fn rejection(remaining: u8, power_cycle_remaining: u8) -> Rejection {
    if remaining == 0 {
        Rejection::Blocked
    } else if power_cycle_remaining == 0 {
        Rejection::PowerCycleBlocked
    } else {
        Rejection::Invalid
    }
}
