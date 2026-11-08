// SPDX-License-Identifier: Apache-2.0
//! Common parameterless command admission for streamed and borrowed requests.
use crate::{config::Command, status::Status};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parameterless {
    GetInfo,
    Reset,
    GetNextAssertion,
    Selection,
}
/// Missing command or extra bytes on a parameterless command fail with the
/// standard length status. Other commands retain their own schema/error policy.
/// The caller supplies only metadata; no input or response backing is retained.
pub fn parameterless(
    command: Option<u8>,
    has_parameters: bool,
) -> Result<Option<Parameterless>, Status> {
    let command = command.ok_or(Status::InvalidLength)?;
    let parsed = match command {
        value if value == Command::GetInfo as u8 => Parameterless::GetInfo,
        value if value == Command::Reset as u8 => Parameterless::Reset,
        value if value == Command::GetNextAssertion as u8 => Parameterless::GetNextAssertion,
        value if value == Command::Selection as u8 => Parameterless::Selection,
        _ => return Ok(None),
    };
    if has_parameters {
        return Err(Status::InvalidLength);
    }
    Ok(Some(parsed))
}
