// SPDX-License-Identifier: Apache-2.0
//! Standard ClientPIN operation sequencing over synchronous product transactions.
use super::request::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Set,
    Change,
    Token,
}
impl Kind {
    pub fn from_command(command: Command) -> Option<Self> {
        match command {
            Command::Set => Some(Self::Set),
            Command::Change => Some(Self::Change),
            Command::Token | Command::TokenPermissions => Some(Self::Token),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    AlreadyConfigured,
    NotConfigured,
    Blocked,
    PowerCycleBlocked,
}
/// Product reads supply durable retries and volatile attempts. Admission runs
/// before agreement or MAC work; durable exhaustion has precedence.
pub struct State {
    pub configured: bool,
    pub retries: u8,
    pub power_cycle_blocked: bool,
}
impl State {
    pub fn admit(&self, kind: Kind) -> Result<(), AdmissionError> {
        if kind == Kind::Set {
            if self.configured {
                return Err(AdmissionError::AlreadyConfigured);
            }
        } else {
            if !self.configured {
                return Err(AdmissionError::NotConfigured);
            }
            if self.retries == 0 {
                return Err(AdmissionError::Blocked);
            }
            if self.power_cycle_blocked {
                return Err(AdmissionError::PowerCycleBlocked);
            }
        }
        Ok(())
    }
}

/// Agreement and current-PIN values use existing product backing. Core lends
/// its key/record scratch and returns unit; a product with zeroizing value types
/// can return those directly. No capability retains a loan or publishes grants.
///
/// prepare_current_pin enters the existing record owner or defers that entry to
/// change/token. Both owners use retry::verify to persist a charge before
/// decrypting/comparing, and refund a correct verifier before new-PIN policy.
/// A prepared verifier is not proof of authority.
/// set/change own new-PIN policy and durable publication; issue_token owns final
/// grant checks, replacement, encryption and reply publication. Product deadline
/// and record ownership checks remain inside those synchronous transactions.
/// Owners erase partial outputs and all temporary secrets on every return.
pub trait Backend {
    type Error;
    type Output;
    type Shared;
    type CurrentPin;
    fn admission_error(error: AdmissionError) -> Self::Error;
    fn state(&mut self) -> Result<State, Self::Error>;
    fn agree(&mut self) -> Result<Self::Shared, Self::Error>;
    fn authenticate_new_pin(
        &mut self,
        shared: &Self::Shared,
        changing: bool,
    ) -> Result<(), Self::Error>;
    fn prepare_current_pin(
        &mut self,
        shared: &Self::Shared,
    ) -> Result<Self::CurrentPin, Self::Error>;
    fn set_pin(&mut self, shared: &Self::Shared) -> Result<Self::Output, Self::Error>;
    fn change_pin(
        &mut self,
        shared: &Self::Shared,
        current: &Self::CurrentPin,
    ) -> Result<Self::Output, Self::Error>;
    fn issue_token(
        &mut self,
        shared: &Self::Shared,
        current: &Self::CurrentPin,
    ) -> Result<Self::Output, Self::Error>;
}

#[inline]
pub fn execute<B: Backend>(kind: Kind, backend: &mut B) -> Result<B::Output, B::Error> {
    backend.state()?.admit(kind).map_err(B::admission_error)?;
    let shared = backend.agree()?;
    if kind != Kind::Token {
        backend.authenticate_new_pin(&shared, kind == Kind::Change)?;
    }
    if kind == Kind::Set {
        return backend.set_pin(&shared);
    }
    let current = backend.prepare_current_pin(&shared)?;
    if kind == Kind::Change {
        backend.change_pin(&shared, &current)
    } else {
        backend.issue_token(&shared, &current)
    }
}
