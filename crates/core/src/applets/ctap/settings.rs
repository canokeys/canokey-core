// SPDX-License-Identifier: Apache-2.0
//! Product record binding and error policy for provisioned COSE identifiers.
use super::Status;
#[cfg(feature = "admin")]
use super::provision::Error;
use crate::ports::Platform;
#[cfg(feature = "admin")]
pub(crate) use canokey_ctap::settings::RECORD_BYTES;
pub(crate) use canokey_ctap::settings::Sm2;

pub(crate) fn load(p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<Sm2, Status> {
    canokey_ctap::settings::load(&mut super::adapter::Settings(p.storage))
        .map_err(|_| Status::Other)
}
#[cfg(feature = "admin")]
pub(crate) fn save(
    wire: &[u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Error> {
    use canokey_ctap::settings::WriteError;
    canokey_ctap::settings::save(wire, &mut super::adapter::Settings(p.storage)).map_err(|error| {
        match error {
            WriteError::Length => Error::Length,
            WriteError::Invalid => Error::Invalid,
            WriteError::Storage => Error::Storage,
        }
    })
}
