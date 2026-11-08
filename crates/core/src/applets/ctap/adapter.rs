// SPDX-License-Identifier: Apache-2.0
//! CanoKey command policy over the product-independent CTAP contracts.
use super::{Command, Status};
use canokey_ctap::request::{self, Parameterless};

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
