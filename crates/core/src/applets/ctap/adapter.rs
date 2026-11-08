// SPDX-License-Identifier: Apache-2.0
//! CanoKey command policy over the product-independent CTAP contracts.
use super::{Command, Status};
use canokey_ctap::request::{self, Parameterless};

/// ADMIN retains authorization and cancellation. This adapter fixes commit to
/// CtapCertificate and exposes neither unrelated records nor general storage.
#[cfg(feature = "admin")]
pub(super) struct CertificateStage<'a, S: ?Sized>(pub &'a mut S);
#[cfg(feature = "admin")]
impl<S: canokey_ports::Storage + ?Sized> canokey_ctap::ports::CertificateStage
    for CertificateStage<'_, S>
{
    type Error = canokey_ports::StorageError;
    fn begin(&mut self) -> Result<(), Self::Error> {
        self.0.stage_begin()
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.stage_append(bytes)
    }
    fn commit(&mut self) -> Result<(), Self::Error> {
        self.0.stage_commit(crate::ports::Record::CtapCertificate)
    }
    fn abort(&mut self) {
        self.0.stage_abort();
    }
}

/// Each window reborrows the existing certificate record; no open handle or
/// payload is retained across transport chunks or workspace replacement.
pub(super) struct Certificate<'a, S: ?Sized>(pub &'a mut S);
impl<S: canokey_ports::Storage + ?Sized> canokey_ctap::ports::Certificate for Certificate<'_, S> {
    type Error = canokey_ports::StorageError;
    fn read(
        &mut self,
        offset: u32,
        output: &mut [u8],
        mode: canokey_ctap::response::ReadMode,
    ) -> Result<usize, Self::Error> {
        match mode {
            canokey_ctap::response::ReadMode::Exact => {
                self.0
                    .read_at(crate::ports::Record::CtapCertificate, offset, output)?;
                Ok(output.len())
            }
            canokey_ctap::response::ReadMode::Partial => {
                self.0
                    .read_some_at(crate::ports::Record::CtapCertificate, offset, output)
            }
        }
    }
}

/// The reader cannot access product records outside FIDO attestation material.
pub(super) struct Attestation<'a, S: ?Sized>(pub &'a mut S);
impl<S: canokey_ports::Storage + ?Sized> canokey_ctap::ports::Attestation for Attestation<'_, S> {
    type Error = canokey_ports::StorageError;
    fn key(
        &mut self,
        out: &mut [u8; canokey_ctap::provision::PRIVATE_KEY_BYTES],
    ) -> Result<usize, Self::Error> {
        self.0.load(crate::ports::Record::CtapAttestationKey, out)
    }
    fn certificate_length(&mut self) -> Result<usize, Self::Error> {
        self.0
            .size(crate::ports::Record::CtapCertificate)
            .map(|length| length as usize)
    }
}

/// The portable settings code can address only this product's SM2 record.
pub(super) struct Settings<'a, S: ?Sized>(pub &'a mut S);
impl<S: canokey_ports::Storage + ?Sized> canokey_ctap::ports::Sm2Settings for Settings<'_, S> {
    fn load(
        &mut self,
        out: &mut [u8; canokey_ctap::settings::RECORD_BYTES],
    ) -> Result<usize, canokey_ports::StorageError> {
        self.0.load(crate::ports::Record::CtapSm2, out)
    }
    fn replace(&mut self, wire: &[u8]) -> Result<(), canokey_ports::StorageError> {
        self.0.replace(crate::ports::Record::CtapSm2, wire)
    }
}

pub(super) fn parameterless(
    code: Option<u8>,
    has_parameters: bool,
) -> Result<Option<Command>, Status> {
    let parsed = request::parameterless(code, has_parameters).map_err(|_| Status::InvalidLength)?;
    Ok(parsed.map(|command| match command {
        Parameterless::GetInfo => Command::GetInfo,
        Parameterless::Reset => Command::Reset,
        Parameterless::GetNextAssertion => Command::NextAssertion,
        Parameterless::Selection => Command::Selection,
    }))
}
