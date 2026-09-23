// SPDX-License-Identifier: Apache-2.0
//! Credential comparison and durable retries, without APDUs or session grants.
use core::ops::Range;

#[cfg(any(feature = "admin", feature = "openpgp"))]
mod record;
#[cfg(any(feature = "openpgp", all(test, feature = "admin")))]
pub(crate) use record::PinInfo;
#[cfg(any(feature = "admin", feature = "openpgp"))]
pub(crate) use record::RecordPin;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Persistence,
    #[cfg(any(feature = "admin", feature = "openpgp"))]
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
    /// `commit` atomically publishes the entire record. Any error is uncertain:
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
        let diff = input
            .iter()
            .zip(stored)
            .fold(input.len() ^ stored.len(), |v, (a, b)| {
                v | usize::from(a ^ b)
            });
        if diff != 0 {
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
