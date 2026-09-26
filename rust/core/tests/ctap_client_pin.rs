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

#[test]
fn unknown_integer_keys_keep_full_width_order_across_fragments() {
    // These labels cannot name a clientPIN field. They must still consume one
    // whole value and participate in ordering without narrowing to eight bits.
    let keys: &[&[u8]] = &[
        &[0x18, 0x7f],
        &[0x18, 0x80],
        &[0x1a, 0xff, 0xff, 0xff, 0xff],
        &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0],
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x20],
        &[0x38, 0x7f],
        &[0x38, 0x80],
        &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ];
    for (i, first) in keys.iter().enumerate() {
        for (j, second) in keys.iter().enumerate() {
            let mut request = vec![6, 0xa3, 2, 1];
            for key in [first, second] {
                request.extend_from_slice(key);
                request.extend_from_slice(&[0x82, 0xa0, 0x41, 7]);
            }
            for split in 0..=request.len() {
                let actual = reply(&[&request[..split], &request[split..]]);
                assert_eq!(
                    actual,
                    if i < j {
                        vec![0, 0xa1, 3, 8]
                    } else {
                        vec![0x12]
                    }
                );
            }
        }
    }
}

#[test]
fn pin_read_failures_never_advertise_unconfigured_state_or_reset_retries() {
    use canokey_rust_core::{applets::ctap::Command, ports::*};
    struct PinStore {
        result: Result<usize, StorageError>,
        retries: u8,
    }
    impl Storage for PinStore {
        fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            if id != Record::CtapPin {
                return Err(StorageError::Missing);
            }
            // Include partial data even on I/O failure; it must not become policy.
            out[..20].fill(0x55);
            out[16..20].copy_from_slice(&[self.retries, 8, 4, 0]);
            self.result
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            panic!("read failure must not replace durable PIN state");
        }
    }
    let mut core = Core::new();
    for (result, retries, failed) in [
        (Ok(20), 6, false),
        (Err(StorageError::Unavailable), 0, true),
        (Err(StorageError::Uncertain), 0, true),
        (Ok(19), 6, true),
        (Ok(20), 9, true),
        (Ok(20), 6, false),
    ] {
        let mut store = PinStore { result, retries };
        let mut p = Platform {
            storage: &mut store,
            crypto: &mut support::Backend::default(),
            device: &mut support::Backend::default(),
            memory: &support::Backend::default(),
        };
        for command in [Command::GetInfo, Command::GetPinRetries] {
            core.begin_ctap(&mut p);
            let is_info = matches!(command, Command::GetInfo);
            let n = core.execute_ctap(Ok(command), &mut p);
            let mut response = vec![0; n];
            core.read_ctap(0, &mut response, &mut p).unwrap();
            if failed {
                assert_eq!(response, [0x7f]);
            } else if is_info {
                assert!(n > 256 && response[0] == 0);
            } else {
                assert_eq!(response, [0, 0xa1, 3, 6]);
            }
            core.close_ctap(&mut p);
        }
    }
}
