// SPDX-License-Identifier: Apache-2.0
// This target depends only on canokey-ctap and its portable contracts.
use canokey_ctap::{
    request::{Parameterless, parameterless},
    status::Status,
};

#[test]
fn parameterless_commands_preserve_exact_length_and_unknown_command_policy() {
    for code in 0x00..=0xff {
        let expected = match code {
            0x04 => Some(Parameterless::GetInfo),
            0x07 => Some(Parameterless::Reset),
            0x08 => Some(Parameterless::GetNextAssertion),
            0x0b => Some(Parameterless::Selection),
            _ => None,
        };
        assert_eq!(parameterless(Some(code), false), Ok(expected));
        assert_eq!(
            parameterless(Some(code), true),
            if expected.is_some() {
                Err(Status::InvalidLength)
            } else {
                Ok(None)
            }
        );
    }
    for has_parameters in [false, true] {
        assert_eq!(
            parameterless(None, has_parameters),
            Err(Status::InvalidLength)
        );
    }
}
