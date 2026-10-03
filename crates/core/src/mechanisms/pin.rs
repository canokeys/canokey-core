// SPDX-License-Identifier: Apache-2.0
//! Credential comparison and durable retries, without APDUs or session grants.
use core::ops::Range;

#[cfg(any(feature = "openpgp", feature = "piv"))]
#[inline(always)]
pub(crate) fn reference(p2: u8, first: u8, second: u8) -> Option<bool> {
    if p2 == first {
        Some(false)
    } else if p2 == second {
        Some(true)
    } else {
        None
    }
}
#[cfg(any(feature = "openpgp", feature = "piv"))]
pub(crate) enum VerifyMode {
    Logout,
    Query,
    Authenticate,
}
#[cfg(any(feature = "openpgp", feature = "piv"))]
#[inline(always)]
pub(crate) fn verify_mode(p1: u8, empty: bool) -> Option<VerifyMode> {
    match p1 {
        0xff => Some(VerifyMode::Logout),
        0x00 if empty => Some(VerifyMode::Query),
        0x00 => Some(VerifyMode::Authenticate),
        _ => None,
    }
}
#[cfg(any(feature = "openpgp", feature = "piv"))]
#[inline(always)]
pub(crate) fn split_change(
    data: &[u8],
    old_bytes: usize,
    new_bytes: Option<usize>,
) -> Option<(&[u8], &[u8])> {
    if data.len() < old_bytes || new_bytes.is_some_and(|n| data.len() - old_bytes != n) {
        return None;
    }
    Some(data.split_at(old_bytes))
}

#[cfg(any(feature = "admin", feature = "openpgp"))]
mod record;
#[cfg(any(feature = "openpgp", all(test, feature = "admin")))]
pub(crate) use record::PinInfo;
#[cfg(any(feature = "admin", feature = "openpgp"))]
pub(crate) use record::RecordPin;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Persistence,
    #[cfg(any(feature = "admin", feature = "openpgp", feature = "piv"))]
    #[cfg_attr(
        all(feature = "piv", not(any(feature = "admin", feature = "openpgp"))),
        expect(dead_code)
    )]
    Length,
    Blocked,
    Retries(u8),
}

#[derive(Clone, Copy)]
pub(crate) enum Charge {
    #[cfg(any(feature = "admin", feature = "piv", test))]
    OnMismatch,
    // A durable decrement must succeed before comparing; success restores it.
    #[cfg(any(feature = "openpgp", test))]
    BeforeCompare,
}

/// A checked view of one credential inside an applet's atomic storage record.
/// No secret copy, storage format conversion or session authorization is owned here.
pub(crate) struct Credential<'a> {
    bytes: &'a mut [u8],
    value: Range<usize>,
    counter: usize,
    limit: u8,
}
impl<'a> Credential<'a> {
    #[cfg(any(feature = "piv", test))]
    pub(crate) fn new(
        bytes: &'a mut [u8],
        value: Range<usize>,
        counter: usize,
        limit: u8,
    ) -> Result<Self, Error> {
        if bytes.get(value.clone()).is_none()
            || limit == 0
            || bytes.get(counter).is_none_or(|n| *n > limit)
            || value.contains(&counter)
        {
            return Err(Error::Persistence);
        }
        Ok(Self {
            bytes,
            value,
            counter,
            limit,
        })
    }
    /// The caller validates protocol lengths and revokes any previous grant.
    /// `commit` atomically persists the changed retry counter. Any error is uncertain:
    /// callers must discard/reload cached state and must not grant authorization.
    pub(crate) fn verify(
        &mut self,
        input: &[u8],
        charge: Charge,
        commit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.bytes[self.counter] == 0 {
            return Err(Error::Blocked);
        }
        let prepaid = match charge {
            #[cfg(any(feature = "admin", feature = "piv", test))]
            Charge::OnMismatch => false,
            #[cfg(any(feature = "openpgp", test))]
            Charge::BeforeCompare => true,
        };
        if prepaid {
            self.bytes[self.counter] -= 1;
            commit(self.bytes)?;
        }
        // Length is public. Compare every supplied/stored overlapping byte,
        // combining the length difference without early exit on secret data.
        let stored = &self.bytes[self.value.clone()];
        if !super::equal(input, stored) {
            if !prepaid {
                self.bytes[self.counter] -= 1;
                commit(self.bytes)?;
            }
            return Err(match self.bytes[self.counter] {
                0 => Error::Blocked,
                n => Error::Retries(n),
            });
        }
        if self.bytes[self.counter] != self.limit {
            self.bytes[self.counter] = self.limit;
            commit(self.bytes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
