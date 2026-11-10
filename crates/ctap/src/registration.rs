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
    /// Prepare the response without publication. Deferred primitive work must
    /// finish successfully before the returned Pending capability is committed.
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

/// Publication uses only the state retained after request processing returns.
/// Implementations discard unpublished staging on failure, including an
/// uncertain commit, without deleting a possibly published credential.
pub trait Publisher<C, P> {
    type Error;
    fn commit(&mut self, credential: &C, publication: &P) -> Result<(), Self::Error>;
    fn abort(&mut self, publication: &P);
}

struct BackendPublisher<'a, B>(&'a mut B);
impl<B: Backend> Publisher<B::Credential, B::Publication> for BackendPublisher<'_, B> {
    type Error = B::Error;
    #[inline(always)]
    fn commit(
        &mut self,
        credential: &B::Credential,
        publication: &B::Publication,
    ) -> Result<(), B::Error> {
        self.0.commit(credential, publication)
    }
    #[inline(always)]
    fn abort(&mut self, publication: &B::Publication) {
        self.0.abort(publication);
    }
}

/// An unpublished transaction, carrying no request/workspace loans. The owner
/// must finish or cancel it before replacing the session or staging another
/// registration. It cannot publish by being dropped.
#[must_use = "unpublished registration must be finished or cancelled"]
pub struct Pending<C, P> {
    credential: C,
    publication: Option<P>,
}
impl<C, P> Pending<C, P> {
    /// An idle/nonresident transaction has no storage publication to finish.
    pub const fn empty(credential: C) -> Self {
        Self {
            credential,
            publication: None,
        }
    }
    pub fn is_resident(&self) -> bool {
        self.publication.is_some()
    }
    /// Drain a session slot without retaining the credential or its publication.
    #[inline(always)]
    pub fn take(&mut self) -> Self
    where
        C: Default,
    {
        Self {
            credential: core::mem::take(&mut self.credential),
            publication: self.publication.take(),
        }
    }
    /// Products whose publication capability already identifies its target
    /// need not retain a duplicate credential across deferred primitive work.
    #[inline(always)]
    pub fn map_credential<T>(self, map: impl FnOnce(C) -> T) -> Pending<T, P> {
        Pending {
            credential: map(self.credential),
            publication: self.publication,
        }
    }
    #[inline(always)]
    pub fn cancel(self, publisher: &mut impl Publisher<C, P>) {
        if let Some(publication) = &self.publication {
            publisher.abort(publication);
        }
    }
    /// Output remains provisional until both response preparation and commit
    /// succeed. An error discards staging only; it never rolls back publication.
    #[inline(always)]
    pub fn finish<T, Q: Publisher<C, P>>(
        self,
        result: Result<T, Q::Error>,
        publisher: &mut Q,
    ) -> Result<T, Q::Error> {
        if let Some(publication) = &self.publication {
            let result = result.and_then(|output| {
                publisher
                    .commit(&self.credential, publication)
                    .map(|()| output)
            });
            if result.is_err() {
                publisher.abort(publication);
            }
            return result;
        }
        result
    }
}

/// Create and stage using borrowed request fields, then release those loans
/// before expensive response work. The returned output may be a framing plan;
/// the owner must pass its final preparation result to Pending::finish.
#[inline(always)]
pub fn prepare<B: Backend>(
    resident: bool,
    backend: &mut B,
) -> Result<(B::Output, Pending<B::Credential, B::Publication>), B::Error> {
    let credential = backend.create()?;
    let publication = if resident {
        Some(backend.stage(&credential)?)
    } else {
        None
    };
    let pending = Pending {
        credential,
        publication,
    };
    match backend.respond(&pending.credential) {
        Ok(output) => Ok((output, pending)),
        Err(error) => {
            pending.cancel(&mut BackendPublisher(backend));
            Err(error)
        }
    }
}

/// Signing/output must succeed before a durable resident credential is installed.
/// Output remains provisional until commit succeeds. Owners erase unpublished
/// output/key backing on failure; a failed commit may have published atomically
/// and cannot authorize compensating writes. No order profile or new backing.
#[inline(always)]
pub fn execute<B: Backend>(resident: bool, mut backend: B) -> Result<B::Output, B::Error> {
    let (output, pending) = prepare(resident, &mut backend)?;
    pending.finish(Ok(output), &mut BackendPublisher(&mut backend))
}
