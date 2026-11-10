// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{Protocol, agreement, response};

fn point() -> [u8; 64] {
    core::array::from_fn(|index| index as u8)
}
fn expected_key() -> Vec<u8> {
    // CTAP 2.1 five-field EC2 agreement key, followed by distinct X and Y.
    let mut bytes = vec![
        0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    bytes.extend(0x00..0x20);
    bytes.extend([0x22, 0x58, 0x20]);
    bytes.extend(0x20..0x40);
    bytes
}
#[test]
fn canonical_key_has_exact_bytes_and_structural_prefix_admission() {
    let expected = expected_key();
    let mut actual = Vec::new();
    agreement::encode(&point(), |fragment| {
        actual.extend_from_slice(fragment);
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), agreement::ENCODED_KEY_BYTES);
    for length in 0..expected.len() {
        assert!(!agreement::is_canonical_prefix(&expected[..length]));
    }
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] ^= 0xff;
        let header = index < 11 || (43..46).contains(&index);
        assert_eq!(agreement::is_canonical_prefix(&changed), !header);
    }
    actual.push(0xff);
    assert!(agreement::is_canonical_prefix(&actual));
}
#[test]
fn retries_encodes_every_unsigned_byte_and_optional_power_cycle_state() {
    for remaining in 0..=u8::MAX {
        for power_cycle in [None, Some(false), Some(true)] {
            let mut actual = Vec::new();
            response::retries(remaining, power_cycle, |fragment| {
                actual.extend_from_slice(fragment);
                Ok::<_, ()>(())
            })
            .unwrap();
            let mut expected = vec![if power_cycle.is_some() { 0xa2 } else { 0xa1 }, 0x03];
            if remaining >= 24 {
                expected.push(0x18);
            }
            expected.push(remaining);
            if let Some(blocked) = power_cycle {
                expected.extend([0x04, if blocked { 0xf5 } else { 0xf4 }]);
            }
            assert_eq!(actual, expected);
        }
    }
}
fn emit_case(case: usize, emit: impl FnMut(&[u8]) -> Result<(), ()>) -> Result<(), ()> {
    match case {
        0 => response::key_agreement(&point(), emit),
        1 => response::retries(8, None, emit),
        2 => response::retries(0xff, Some(true), emit),
        3 => response::token(Protocol::One, &[0x6d; 48], emit),
        4 => response::token(Protocol::Two, &[0x6d; 48], emit),
        _ => unreachable!(),
    }
}
fn expected_case(case: usize) -> Vec<u8> {
    match case {
        0 => [vec![0xa1, 0x01], expected_key()].concat(),
        1 => vec![0xa1, 0x03, 0x08],
        2 => vec![0xa2, 0x03, 0x18, 0xff, 0x04, 0xf5],
        3 => [vec![0xa1, 0x02, 0x58, 0x20], vec![0x6d; 32]].concat(),
        4 => [vec![0xa1, 0x02, 0x58, 0x30], vec![0x6d; 48]].concat(),
        _ => unreachable!(),
    }
}
#[test]
fn complete_responses_preserve_bounded_output_and_stop_at_first_sink_failure() {
    for case in 0..5 {
        let expected = expected_case(case);
        for capacity in 0..=expected.len() + 1 {
            let mut backing = [0xa7; 96];
            let mut cursor = 0;
            let result = emit_case(case, |fragment| {
                if cursor + fragment.len() > capacity {
                    return Err(());
                }
                backing[cursor..cursor + fragment.len()].copy_from_slice(fragment);
                cursor += fragment.len();
                Ok(())
            });
            assert_eq!(result.is_ok(), capacity >= expected.len());
            assert_eq!(&backing[..cursor], &expected[..cursor]);
            assert!(backing[cursor..].iter().all(|byte| *byte == 0xa7));
        }
        let mut fragments = 0;
        emit_case(case, |_| {
            fragments += 1;
            Ok(())
        })
        .unwrap();
        for fail_at in 1..=fragments {
            let mut calls = 0;
            let result = emit_case(case, |_| {
                calls += 1;
                if calls == fail_at { Err(()) } else { Ok(()) }
            });
            assert_eq!(result, Err(()));
            assert_eq!(calls, fail_at);
        }
    }
}
