// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ctap")]
use canokey_rust_core::{Core, applets::ctap::Request};
#[path = "support/ctap.rs"]
mod support;

fn reply(parts: &[&[u8]]) -> Vec<u8> {
    let mut request = Request::new();
    for bytes in parts {
        request.consume(bytes);
    }
    support::execute(&mut Core::new(), request.finish())
}

#[test]
fn retry_query_and_skipped_values_across_all_splits() {
    for request in [
        vec![6, 0xa1, 2, 1],
        vec![6, 0xa2, 1, 1, 2, 1],
        vec![6, 0xa2, 1, 2, 2, 1],
        // Unknown extension array/map/text/bytes, ending in a large byte string.
        [
            vec![
                6, 0xa2, 2, 1, 0x18, 0x63, 0x82, 0xa1, 0, 0x62, b'o', b'k', 0x59, 1, 0,
            ],
            vec![0x37; 256],
        ]
        .concat(),
    ] {
        for split in 0..=request.len() {
            assert_eq!(
                reply(&[&request[..split], &[], &request[split..]]),
                &[0, 0xa1, 3, 8]
            );
        }
        assert_eq!(
            reply(&request.chunks(1).collect::<Vec<_>>()),
            &[0, 0xa1, 3, 8]
        );
        for length in 1..request.len() {
            assert_ne!(reply(&[&request[..length]])[0], 0);
        }
    }
}

#[test]
fn client_pin_error_mapping_and_terminal_failure() {
    let cases: &[(&[u8], u8)] = &[
        (&[6], 0x12),
        (&[6, 0xa0], 0x14),
        (&[6, 0x80], 0x11),
        (&[6, 0xa1, 2, 0xf5], 0x11),
        (&[6, 0xa1, 2, 0x20], 0x3e),
        (&[6, 0xa1, 2, 0x18, 0x7f], 0x3e),
        (&[6, 0xa1, 2, 2], 0x14),
        (&[6, 0xa2, 1, 3, 2, 1], 2),
        (&[6, 0xa2, 1, 0x61, b'x', 2, 1], 0x11),
        (&[6, 0xa2, 2, 1, 2, 1], 0x12),          // duplicate
        (&[6, 0xa2, 2, 1, 1, 1], 0x12),          // unsorted
        (&[6, 0xa1, 0x18, 2, 1], 0x12),          // overlong key
        (&[6, 0xa1, 2, 1, 0], 0x12),             // trailing item
        (&[6, 0xa1, 0x61, b'x', 1], 0x11),       // noninteger key
        (&[6, 0xa2, 2, 1, 7, 0x61, 0x80], 0x12), // invalid unknown text
    ];
    for &(request, expected) in cases {
        for split in 0..=request.len() {
            assert_eq!(
                reply(&[&request[..split], &request[split..]]),
                &[expected],
                "{request:x?}"
            );
        }
    }
    assert_eq!(reply(&[&[6, 0x80], &[0xa1, 2, 1]]), &[0x11]);
}

#[test]
fn agreement_survives_response_cleanup_but_not_session_reset() {
    let mut core = Core::new();
    let mut crypto = support::Backend::default();
    support::with_platform(&mut crypto, |p| {
        for _ in 0..2 {
            core.begin_ctap(p);
            let n = core.execute_ctap(
                Ok(canokey_rust_core::applets::ctap::Command::GetKeyAgreement),
                p,
            );
            let mut bytes = vec![0; n];
            for (index, chunk) in bytes.chunks_mut(13).enumerate() {
                core.read_ctap(index * 13, chunk, p).unwrap();
            }
            assert_eq!(
                &bytes[..16],
                &[
                    0, 0xa1, 1, 0xa5, 1, 2, 3, 0x38, 24, 0x20, 1, 0x21, 0x58, 32, 8, 8
                ]
            );
            assert_eq!(n, 81);
            core.close_ctap(p);
        }
        core.reset(p);
        core.begin_ctap(p);
        core.execute_ctap(
            Ok(canokey_rust_core::applets::ctap::Command::GetKeyAgreement),
            p,
        );
    });
    assert_eq!(crypto.generated, 2);
}
