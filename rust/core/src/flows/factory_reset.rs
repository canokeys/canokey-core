// SPDX-License-Identifier: Apache-2.0
//! Persistent reset orchestration. Runtime revokes sessions and verifies presence.
use super::Error;
use crate::{
    Platform,
    applets::{admin::pin, pass::service::Pass},
};
#[cfg(feature = "oath")]
pub fn oath(pass: Option<&mut Pass>, p: &mut Platform<'_>) -> Result<(), Error> {
    if let Some(pass) = pass {
        pass.remove_oath(None, p.storage, p.memory)
            .map_err(Error::Pass)?;
    }
    crate::applets::oath::repository::reset(p.storage, p.crypto, p.memory).map_err(Error::Oath)
}
pub fn run(mut pass: Option<&mut Pass>, p: &mut Platform<'_>) -> Result<(), Error> {
    // PIN last: a partially completed reset remains locked and retryable.
    if let Some(pass) = &mut pass {
        pass.clear(p.storage, p.memory).map_err(Error::Pass)?;
    }
    #[cfg(feature = "oath")]
    oath(pass, p)?;
    #[cfg(feature = "openpgp")]
    crate::applets::openpgp::repository::reset(p).map_err(Error::OpenPgp)?;
    pin::factory_reset(p).map_err(Error::Admin)
}
