// SPDX-License-Identifier: Apache-2.0
//! Token owner, shared admission and clocks; products lend primitive capabilities.
mod state;
pub use state::Token;

#[derive(Clone, Copy)]
pub enum MissingRp {
    Allow,
    Deny,
}

/// RP hashes are public metadata. The comparator lets a product retain its
/// selected constant-time primitive; token material is lent only to MAC work.
pub struct Scope<'a> {
    pub granted: u16,
    pub required: u16,
    pub bound_rp: Option<&'a [u8; 32]>,
    pub requested_rp: Option<&'a [u8; 32]>,
    pub missing_rp: MissingRp,
}
impl Scope<'_> {
    fn permission_allowed(&self) -> bool {
        self.required != 0x00 && self.granted & self.required == self.required
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

/// Admit all requested permission bits and RP scope before verifying the MAC.
/// A successful return authorizes the owner to commit usage/RP metadata only
/// after any deferred credential-RP resolution also succeeds. Closures are
/// synchronous and must not reenter the application or retain loans.
#[inline]
pub fn authorize<E>(
    scope: Scope<'_>,
    verify: impl FnOnce() -> Result<(), E>,
    equal: impl FnOnce(&[u8], &[u8]) -> bool,
) -> Result<(), Error<E>> {
    if !scope.permission_allowed() || !scope.rp_allowed(equal) {
        return Err(Error::Scope);
    }
    verify().map_err(Error::Mac)
}

/// Standard CTAP token limits, measured from issuance and the last successful
/// authenticated use. Queries and failed authentication refresh neither clock.
pub const IDLE_MS: u32 = 30_000;
pub const LIFETIME_MS: u32 = 600_000;

/// Standard tokens expire at either exact boundary, including across tick wrap.
/// Issuance initializes both origins; a successful use changes last_used only.
/// The owner retains all clock metadata and revokes/wipes expired token state.
#[inline]
pub fn lifetime_remaining(now: u32, issued: u32, last_used: u32) -> Option<u32> {
    let idle = remaining_ms(now, last_used, IDLE_MS)?;
    let absolute = remaining_ms(now, issued, LIFETIME_MS)?;
    Some(idle.min(absolute))
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
