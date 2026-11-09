// SPDX-License-Identifier: Apache-2.0
//! Credential-list selection and exclusion/presence flow before response work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// Owned streamed requests have already validated the complete list.
    First,
    /// Decode the remaining descriptors, without opening more credentials.
    ValidateTail,
}
/// Select the first usable ordinary credential. Products own handle/point/record
/// checks and lend existing key/root scratch; invalid foreign handles yield None.
/// Borrowed lists still validate all descriptors after a match, but never open
/// another credential. Owned lists may stop immediately after a match.
#[inline]
pub fn listed<I, T, E>(
    candidates: impl IntoIterator<Item = Result<Option<I>, E>>,
    walk: Walk,
    mut open: impl FnMut(I) -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    let mut selected = None;
    for candidate in candidates {
        let Some(candidate) = candidate? else {
            continue;
        };
        if selected.is_some() {
            continue;
        }
        if let Some(found) = open(candidate)? {
            if selected.is_none() {
                selected = Some(found);
            }
            if walk == Walk::First {
                break;
            }
        }
    }
    Ok(selected)
}

/// One synchronous operation owns its existing request/context/workspace loans.
/// select retains product selection and scan/count/cursor state. presence(false)
/// may only recheck a product deadline; consume_presence runs after a successful
/// actual gesture. complete owns extension preparation, create/assert, signing,
/// persistent/cursor publication and response output at product commit points.
/// This capability cannot publish native or role-ticket authority.
pub trait Backend {
    type Error;
    type Output;
    fn select(&mut self) -> Result<bool, Self::Error>;
    fn presence(&mut self, up: bool) -> Result<(), Self::Error>;
    fn excluded(result: Result<(), Self::Error>) -> Self::Error;
    fn no_credentials() -> Self::Error;
    fn consume_presence(&mut self);
    fn complete(self) -> Result<Self::Output, Self::Error>;
}
#[inline]
pub fn execute<B: Backend>(make: bool, up: bool, mut backend: B) -> Result<B::Output, B::Error> {
    let matched = backend.select()?;
    if make && matched {
        let presence = backend.presence(true);
        return Err(B::excluded(presence));
    }
    if !make && !matched {
        return Err(B::no_credentials());
    }
    backend.presence(up)?;
    if up {
        backend.consume_presence();
    }
    backend.complete()
}
