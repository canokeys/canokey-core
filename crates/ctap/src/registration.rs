// SPDX-License-Identifier: Apache-2.0
//! Registration transaction sequencing over product-owned credential and reply
//! backing. Presence and authorization must complete before entry.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// The durable credential exists even if subsequent signing/output fails.
    BeforeResponse,
    /// Signing/output must succeed before a durable credential is installed.
    /// Output remains provisional until this transaction returns successfully.
    AfterResponse,
}

pub trait Backend {
    type Error;
    type Credential;
    type Output;
    fn create(&mut self) -> Result<Self::Credential, Self::Error>;
    fn commit(&mut self, credential: &Self::Credential) -> Result<(), Self::Error>;
    fn respond(&mut self, credential: &Self::Credential) -> Result<Self::Output, Self::Error>;
}

/// Preserve the explicit product commit point without compensating writes.
/// On failure the caller owns unpublished output erasure and key cleanup. The
/// credential value is the existing product handle/key owner, not a new copy;
/// no session, response lease or transport ownership survives this call.
#[inline(always)]
pub fn execute<B: Backend>(
    resident: bool,
    commit: Commit,
    mut backend: B,
) -> Result<B::Output, B::Error> {
    let credential = backend.create()?;
    if resident && commit == Commit::BeforeResponse {
        backend.commit(&credential)?;
    }
    let output = backend.respond(&credential)?;
    if resident && commit == Commit::AfterResponse {
        backend.commit(&credential)?;
    }
    Ok(output)
}
