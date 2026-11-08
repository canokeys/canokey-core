// SPDX-License-Identifier: Apache-2.0
//! Token admission over owner-held metadata; no secret or session storage.

/// Products preserve their first-error and primitive-call ordering.
#[derive(Clone, Copy)]
pub enum Order {
    ScopeThenMac,
    MacThenScope,
    PermissionThenMacThenRp,
}
#[derive(Clone, Copy)]
pub enum PermissionMatch {
    All,
    Any,
}
#[derive(Clone, Copy)]
pub enum MissingRp {
    Allow,
    Deny,
}

/// RP hashes are public metadata. The comparator lets a product retain its
/// existing constant-time primitive without moving secret storage here.
pub struct Scope<'a> {
    pub granted: u16,
    pub required: u16,
    pub permission_match: PermissionMatch,
    pub bound_rp: Option<&'a [u8; 32]>,
    pub requested_rp: Option<&'a [u8; 32]>,
    pub missing_rp: MissingRp,
}
impl Scope<'_> {
    fn permission_allowed(&self) -> bool {
        match self.permission_match {
            PermissionMatch::All => self.granted & self.required == self.required,
            PermissionMatch::Any => self.granted & self.required != 0x00,
        }
    }
    fn rp_allowed(&self, equal: impl FnOnce(&[u8], &[u8]) -> bool) -> bool {
        match (self.bound_rp, self.requested_rp) {
            (None, _) => true,
            (Some(bound), Some(requested)) => equal(bound, requested),
            (Some(_), None) => matches!(self.missing_rp, MissingRp::Allow),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Scope,
    Mac(E),
}

/// Verifies once in the selected order. A failed MAC or scope never commits a
/// use, RP binding or deadline refresh; owners do so at their established point.
/// Closures are synchronous and must not reenter the application or retain loans.
#[inline]
pub fn authorize<E>(
    scope: Scope<'_>,
    order: Order,
    verify: impl FnOnce() -> Result<(), E>,
    equal: impl FnOnce(&[u8], &[u8]) -> bool,
) -> Result<(), Error<E>> {
    match order {
        Order::ScopeThenMac => {
            if !scope.permission_allowed() || !scope.rp_allowed(equal) {
                return Err(Error::Scope);
            }
            verify().map_err(Error::Mac)
        }
        Order::MacThenScope => {
            verify().map_err(Error::Mac)?;
            if !scope.permission_allowed() || !scope.rp_allowed(equal) {
                return Err(Error::Scope);
            }
            Ok(())
        }
        Order::PermissionThenMacThenRp => {
            if !scope.permission_allowed() {
                return Err(Error::Scope);
            }
            verify().map_err(Error::Mac)?;
            if !scope.rp_allowed(equal) {
                return Err(Error::Scope);
            }
            Ok(())
        }
    }
}

/// Remaining milliseconds in a wrapping clock window. Products choose origins,
/// limits and whether successful use refreshes or disables a window. The exact
/// limit is expired; this function never mutates or revokes owner state.
#[inline]
pub fn remaining_ms(now: u32, started: u32, limit_ms: u32) -> Option<u32> {
    let elapsed = now.wrapping_sub(started);
    if elapsed >= limit_ms {
        None
    } else {
        Some(limit_ms - elapsed)
    }
}

/// Successful UP consumes only the product-selected permissions. Native grants
/// and optional standard permissions are retained only when explicitly selected.
#[inline]
pub fn after_presence(granted: u16, retained: u16) -> u16 {
    granted & retained
}
