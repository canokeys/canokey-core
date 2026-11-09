// SPDX-License-Identifier: Apache-2.0
//! MakeCredential/GetAssertion PIN/UV admission before credential selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretOrder {
    BeforePolicy,
    AfterEmptyAuthentication,
}
/// Borrowed/streamed schemas retain their own option admission. These choices
/// preserve runtime error/read precedence without installing another engine.
pub struct Profile {
    pub secret_order: SecretOrder,
    pub reject_assertion_resident: bool,
}
pub struct Request {
    pub make: bool,
    pub up: bool,
    pub uv: bool,
    pub resident: bool,
    pub auth_length: Option<usize>,
    pub secret: bool,
    pub large_blob_key: bool,
}
pub struct Policy {
    pub pin_set: bool,
    pub always_uv: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
    PinInvalid,
    PinNotSet,
    UnsupportedOption,
    InvalidOption,
    PuatRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E> {
    Rule(RuleError),
    Backend(E),
}
impl<E> From<RuleError> for Error<E> {
    fn from(error: RuleError) -> Self {
        Self::Rule(error)
    }
}
/// Only the serialized owner reads policy, services a credential presence probe
/// or verifies its existing token. No request/secret backing or grant is stored.
/// Authorization may be a product deadline or unit for an already bound session.
/// Returning a value means token admission succeeded, never that UP occurred.
pub trait Backend {
    type Error;
    type Authorization;
    fn policy(&mut self) -> Result<Policy, Self::Error>;
    fn presence(&mut self) -> Result<(), Self::Error>;
    fn verify(&mut self) -> Result<Self::Authorization, Self::Error>;
}
fn silent_secret(request: &Request) -> Result<(), RuleError> {
    if !request.make && !request.up && request.secret {
        return Err(RuleError::UnsupportedOption);
    }
    Ok(())
}
#[inline]
pub fn authorize<B: Backend>(
    request: &Request,
    profile: Profile,
    backend: &mut B,
) -> Result<Option<B::Authorization>, Error<B::Error>> {
    if profile.secret_order == SecretOrder::BeforePolicy {
        silent_secret(request)?;
    }
    let policy = backend.policy().map_err(Error::Backend)?;
    if request.auth_length == Some(0) {
        backend.presence().map_err(Error::Backend)?;
        return Err(if policy.pin_set {
            RuleError::PinInvalid
        } else {
            RuleError::PinNotSet
        }
        .into());
    }
    if profile.secret_order == SecretOrder::AfterEmptyAuthentication {
        silent_secret(request)?;
    }
    if request.make && request.large_blob_key && !request.resident {
        return Err(RuleError::InvalidOption.into());
    }
    if (request.uv && request.auth_length.is_none())
        || (request.make && !request.up)
        || (profile.reject_assertion_resident && !request.make && request.resident)
    {
        return Err(RuleError::InvalidOption.into());
    }
    if request.auth_length.is_some() {
        if !policy.pin_set {
            return Err(RuleError::PinNotSet.into());
        }
        return backend.verify().map(Some).map_err(Error::Backend);
    }
    if policy.always_uv || (policy.pin_set && request.make && request.resident) {
        return Err(RuleError::PuatRequired.into());
    }
    Ok(None)
}
