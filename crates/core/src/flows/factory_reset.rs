// SPDX-License-Identifier: Apache-2.0
//! Persistent reset orchestration. Runtime revokes sessions and verifies presence.
use super::Error;
use crate::{
    Platform,
    applets::{admin::pin, pass::service::Pass},
    runtime::workspace::SessionWorkspace,
};
#[cfg(feature = "ctap")]
pub fn ctap(
    ctap: &mut crate::applets::ctap::Applet,
    workspace: &mut SessionWorkspace,
    p: &mut Platform<'_>,
) -> Result<(), Error> {
    ctap.reset_persistent(workspace, p).map_err(|_| Error::Ctap)
}
#[cfg(feature = "ndef")]
pub fn ndef(p: &mut Platform<'_>) -> Result<(), Error> {
    crate::applets::ndef::reset_persistent(p).map_err(|_| Error::Ndef)
}
#[cfg(feature = "openpgp")]
pub fn openpgp(workspace: &mut SessionWorkspace, p: &mut Platform<'_>) -> Result<(), Error> {
    let workspace = workspace.classic_with(p.memory);
    p.memory.wipe(&mut workspace.key.bytes);
    p.memory.wipe(workspace.input);
    crate::applets::openpgp::repository::reset(p).map_err(Error::OpenPgp)
}
#[cfg(feature = "piv")]
pub fn piv(workspace: &mut SessionWorkspace, p: &mut Platform<'_>) -> Result<(), Error> {
    let mut piv = crate::applets::piv::Piv::new();
    piv.reset(workspace, p);
    piv.reset_persistent(p).map_err(|_| Error::Piv)
}
#[cfg(feature = "oath")]
pub fn oath(pass: Option<&mut Pass>, p: &mut Platform<'_>) -> Result<(), Error> {
    // Remove keyboard references first, so a partial OATH reset cannot leave
    // PASS pointing at an erased or subsequently reused credential record.
    if let Some(pass) = pass {
        pass.remove_oath(None, p.storage, p.memory)
            .map_err(Error::Pass)?;
    }
    crate::applets::oath::repository::reset(p.storage, p.crypto, p.memory).map_err(Error::Oath)
}
pub fn run(
    mut pass: Option<&mut Pass>,
    #[cfg(feature = "ctap")] ctap: &mut crate::applets::ctap::Applet,
    #[cfg(feature = "piv")] piv: &mut crate::applets::piv::Piv,
    workspace: &mut SessionWorkspace,
    p: &mut Platform<'_>,
) -> Result<(), Error> {
    let _ = &workspace;
    #[cfg(feature = "ndef")]
    ndef(p)?;
    #[cfg(feature = "ctap")]
    self::ctap(ctap, workspace, p)?;
    // PIN last: a partially completed reset remains locked and retryable.
    if let Some(pass) = &mut pass {
        pass.clear(p.storage, p.memory).map_err(Error::Pass)?;
    }
    #[cfg(feature = "oath")]
    oath(pass, p)?;
    #[cfg(feature = "openpgp")]
    crate::applets::openpgp::repository::reset(p).map_err(Error::OpenPgp)?;
    #[cfg(feature = "piv")]
    piv.reset_persistent(p).map_err(|_| Error::Piv)?;
    pin::factory_reset(p).map_err(Error::Admin)
}

#[cfg(all(
    test,
    feature = "pass",
    feature = "oath",
    feature = "ctap",
    feature = "piv",
    feature = "openpgp",
    feature = "ndef",
    any(not(feature = "static-backend"), feature = "dynamic-backend")
))]
mod tests;
