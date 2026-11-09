// SPDX-License-Identifier: Apache-2.0
//! Exercise the product parser, including commands intentionally absent in vLEI.
#![cfg(feature = "ctap")]

use canokey_rust_core::applets::ctap::{Command, Request, Status};

// CTAP 2.3 section 6 command bytes, plus the supported CTAP 2.1 preview alias.
const PRODUCT_COMMANDS: &[u8] = &[
    0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x41,
];

#[test]
fn product_parser_admits_only_its_declared_command_set_at_every_split() {
    // A0 is an empty parameter map. Parameterless commands reject it as extra
    // input; parameterized commands reach their own required-field admission.
    for code in 0x00..=0xff {
        for bytes in [&[code][..], &[code, 0xa0][..]] {
            for split in 0..=bytes.len() {
                let mut request = Request::new();
                request.consume(&bytes[..split]);
                request.consume(&bytes[split..]);
                let result = request.finish();
                assert_eq!(
                    !matches!(result, Err(Status::UnhandledRequest)),
                    // CanoKey preserves its C-compatible bare config status;
                    // supplying a map reaches config's required-field parser.
                    PRODUCT_COMMANDS.contains(&code) && (code != 0x0d || bytes.len() > 1),
                    "command {code:#04x}, split {split}"
                );
            }
        }
    }
}

#[test]
fn parameterless_commands_reject_all_extra_bytes_before_schema_dispatch() {
    for code in [0x04, 0x07, 0x08, 0x0b] {
        let mut request = Request::new();
        request.consume(&[code]);
        let parsed = request
            .finish()
            .unwrap_or_else(|status| panic!("{status:?}"));
        assert!(matches!(
            (code, parsed),
            (0x04, Command::GetInfo)
                | (0x07, Command::Reset)
                | (0x08, Command::NextAssertion)
                | (0x0b, Command::Selection)
        ));
        for extra in 0x00..=0xff {
            for split in 0..=2 {
                let bytes = [code, extra];
                let mut request = Request::new();
                request.consume(&bytes[..split]);
                request.consume(&bytes[split..]);
                assert!(matches!(request.finish(), Err(Status::InvalidLength)));
            }
        }
    }
    assert!(matches!(
        Request::new().finish(),
        Err(Status::InvalidLength)
    ));
}
