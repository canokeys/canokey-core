// SPDX-License-Identifier: Apache-2.0
//! Ordinary assertion/packed-attestation sequencing over existing product loans.
//! Material selection and native primitives remain explicit capabilities; the
//! engine chooses fallback and prevents output after material/signing failure.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statement {
    Assertion,
    SelfAttestation,
    Provisioned { certificate: usize },
}
impl Statement {
    pub const fn certificate_length(self) -> usize {
        match self {
            Self::Provisioned { certificate } => certificate,
            _ => 0,
        }
    }
    pub const fn provisioned(self) -> bool {
        matches!(self, Self::Provisioned { .. })
    }
}
#[derive(Clone, Copy)]
pub enum Unprovisioned {
    /// Sign with the already selected credential key (Core's existing owner).
    SignCredential,
    /// Return to the caller before signing (the borrowed product's self path).
    Return,
}
/// No capability or signature backing outlives this synchronous operation.
/// Signature may be a length in an existing workspace or a native return value.
/// respond consumes the adapter only after successful signing; it retains the
/// product's immediate certificate reload or deferred response-lease metadata.
pub trait Backend {
    type Error;
    type Signature;
    type Output;
    fn select(&mut self) -> Result<usize, Self::Error>;
    /// Provisioned statements use P-256; other statements use the selected
    /// credential's admitted algorithm. The capability owns native error mapping.
    fn sign(&mut self, statement: Statement) -> Result<Self::Signature, Self::Error>;
    fn respond(
        self,
        statement: Statement,
        signature: Self::Signature,
    ) -> Result<Self::Output, Self::Error>;
}

/// Assertions never read attestation material. An admitted nonzero certificate
/// selects provisioned P-256; zero follows the explicit existing owner profile.
/// Output and final publication cannot run after selection/signature failure.
#[inline(always)]
pub fn execute<B: Backend>(
    make: bool,
    fallback: Unprovisioned,
    mut backend: B,
) -> Result<Option<B::Output>, B::Error> {
    let statement = if make {
        let certificate = backend.select()?;
        if certificate == 0 {
            if matches!(fallback, Unprovisioned::Return) {
                return Ok(None);
            }
            Statement::SelfAttestation
        } else {
            Statement::Provisioned { certificate }
        }
    } else {
        Statement::Assertion
    };
    let signature = backend.sign(statement)?;
    backend.respond(statement, signature).map(Some)
}
