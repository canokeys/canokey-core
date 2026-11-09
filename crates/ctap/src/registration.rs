// SPDX-License-Identifier: Apache-2.0
//! Registration transaction sequencing over product-owned credential and reply
//! backing. Presence and authorization must complete before entry.

pub trait Backend {
    type Error;
    type Credential;
    type Publication;
    type Output;
    fn create(&mut self) -> Result<Self::Credential, Self::Error>;
    /// Prepare unpublished resident state over existing scratch. Products that
    /// can write after response preparation may return an empty capability.
    fn stage(&mut self, credential: &Self::Credential) -> Result<Self::Publication, Self::Error>;
    /// Complete signing and fallible response preparation without publication.
    fn respond(&mut self, credential: &Self::Credential) -> Result<Self::Output, Self::Error>;
    fn commit(
        &mut self,
        credential: &Self::Credential,
        publication: &Self::Publication,
    ) -> Result<(), Self::Error>;
    /// Discard unpublished state after response or uncertain commit failure.
    /// No rollback of an already published credential is attempted.
    fn abort(&mut self, publication: &Self::Publication);
}

/// Signing/output must succeed before a durable resident credential is installed.
/// Output remains provisional until commit succeeds. Owners erase unpublished
/// output/key backing on failure; a failed commit may have published atomically
/// and cannot authorize compensating writes. No order profile or new backing.
#[inline(always)]
pub fn execute<B: Backend>(resident: bool, mut backend: B) -> Result<B::Output, B::Error> {
    let credential = backend.create()?;
    let publication = if resident {
        Some(backend.stage(&credential)?)
    } else {
        None
    };
    let mut result = backend.respond(&credential);
    if let Some(publication) = &publication {
        if result.is_ok() {
            if let Err(error) = backend.commit(&credential, publication) {
                result = Err(error);
            }
        }
        if result.is_err() {
            backend.abort(publication);
        }
    }
    result
}
