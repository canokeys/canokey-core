// SPDX-License-Identifier: Apache-2.0
//! CanoKey command policy over the product-independent CTAP contracts.
use super::{Command, Status};
use canokey_ctap::request::{self, Parameterless};

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
