// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::ports::*;
use sha2::{Digest, Sha256};
use std::{vec, vec::Vec};

#[derive(Default)]
struct Backend {
    record: Vec<u8>,
    writes: usize,
    fail: bool,
    read_fail: bool,
    now: u32,
    expected_message: Vec<u8>,
    expected_key: Option<[u8; 32]>,
}
impl Storage for Backend {
    fn load(&mut self, _: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        if self.record.is_empty() {
            return Err(StorageError::Missing);
        }
        out[..self.record.len()].copy_from_slice(&self.record);
        if self.read_fail {
            Err(StorageError::Unavailable)
        } else {
            Ok(self.record.len())
        }
    }
    fn replace(&mut self, _: Record, bytes: &[u8]) -> Result<(), StorageError> {
        self.writes += 1;
        if self.fail {
            return Err(StorageError::Unavailable);
        }
        self.record = bytes.to_vec();
        Ok(())
    }
}
impl Crypto for Backend {
    fn mac(
        &mut self,
        alg: u8,
        key: &[u8],
        message: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        assert_eq!(alg, 2);
        assert_eq!(key, self.expected_key.unwrap_or([7; 32]));
        assert_eq!(message, self.expected_message);
        out[..32].fill(0x5a);
        Ok(())
    }
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&Sha256::digest(input));
        Ok(())
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.fill(7);
        Ok(())
    }
    // These tests exercise policy and state transitions, not AES/ECDH.
    fn aes256_cbc(
        &mut self,
        _: bool,
        _: &[u8; 32],
        _: &[u8; 16],
        _: &mut [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
    fn key_operation(
        &mut self,
        op: KeyOperation,
        _: u8,
        _: &mut KeyMaterial,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(matches!(op, KeyOperation::Agree));
        out[..32].fill(7);
        Ok(32)
    }
}
impl Device for Backend {
    fn progress(&mut self) -> bool {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        self.now
    }
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn led(&mut self, _: bool) {}
}
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

#[test]
fn pin_record_reads_initialize_tail_and_wipe_failed_data() {
    let mut store = Backend::default();
    let mut crypto = Backend::default();
    let mut device = Backend::default();
    let memory = Backend::default();
    let mut output = [0xcc; pin::RECORD_BYTES];
    let mut read = |store: &mut Backend, output: &mut [u8; pin::RECORD_BYTES]| {
        pin::load(
            &mut Platform {
                storage: store,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            },
            output,
        )
    };
    assert_eq!(read(&mut store, &mut output), Ok(()));
    let mut expected = [0; pin::RECORD_BYTES];
    expected[pin::RETRIES] = 8;
    expected[pin::MIN_PIN_LENGTH] = 4;
    assert_eq!(output, expected);

    // No RP hashes: a short valid record must not retain a previous caller's tail.
    expected[..16].fill(0x5a);
    expected[pin::PIN_LENGTH] = 8;
    store.record = expected[..pin::RP_HASHES].to_vec();
    output.fill(0xcc);
    assert_eq!(read(&mut store, &mut output), Ok(()));
    assert_eq!(output, expected);

    for (length, byte, value, read_fail) in [
        (19, pin::RETRIES, 8, false),
        (20, pin::RETRIES, 9, false),
        (20, pin::PIN_LENGTH, 3, false),
        (20, pin::MIN_PIN_LENGTH, 3, false),
        (20, pin::FLAGS, 5 << pin::RP_HASH_COUNT_SHIFT, false),
        (20, pin::FLAGS, 1 << pin::RP_HASH_COUNT_SHIFT, false),
        // The backend copied a secret prefix before reporting an I/O failure.
        (7, pin::RETRIES, 8, true),
    ] {
        let mut bytes = expected;
        bytes[byte] = value;
        store.record = bytes[..length].to_vec();
        store.read_fail = read_fail;
        output.fill(0xcc);
        assert_eq!(read(&mut store, &mut output), Err(Status::Other));
        assert_eq!(output, [0; pin::RECORD_BYTES]);
        assert_eq!(store.writes, 0);
    }
}

fn run(
    session: &mut Session,
    parts: &[&[u8]],
    store: &mut Backend,
    crypto: &mut Backend,
    now: u32,
) -> u8 {
    let mut request = super::super::Request::new();
    for part in parts {
        request.consume(part);
    }
    let mut w = Workspace::new();
    let mut command = request.finish();
    let response = session.execute(
        &mut command,
        &mut w,
        &mut Platform {
            storage: store,
            crypto,
            device: &mut Backend {
                now,
                ..Backend::default()
            },
            memory: &Backend::default(),
        },
    );
    let mut status = [0];
    response.read(&w, 0, &mut status, store).unwrap();
    status[0]
}
#[test]
fn configuration_streams_exact_authenticated_map_at_every_split() {
    // Include an unknown nested parameter, UTF-8, and a split length header.
    let mut params = vec![0xa4, 1, 8, 2, 0x82, 0x63, 0xe4, 0xbe, 0x8b, 0x78, 24];
    params.extend_from_slice(&[b'a'; 24]);
    params.extend_from_slice(&[3, 0xf4, 4, 0x81, 0xa1, 1, 0x40]);
    for protocol in [1, 2] {
        let mut request = vec![0x0d, 0xa4, 1, 3, 2];
        request.extend_from_slice(&params);
        request.extend_from_slice(&[3, protocol, 4]);
        let auth_len = if protocol == 1 {
            request.push(0x50);
            16
        } else {
            request.extend_from_slice(&[0x58, 32]);
            32
        };
        request.extend_from_slice(&vec![0x5a; auth_len]);
        let mut message = vec![0xff; 32];
        message.extend_from_slice(&[0x0d, 3]);
        message.extend_from_slice(&params);
        for split in 0..=request.len() {
            let mut session = Session::new();
            session.permissions = 0x20;
            session.token.fill(7);
            let mut store = Backend {
                record: vec![0; 20],
                ..Backend::default()
            };
            store.record[16..20].copy_from_slice(&[8, 6, 4, 0]);
            let mut crypto = Backend {
                expected_message: message.clone(),
                ..Backend::default()
            };
            assert_eq!(
                run(
                    &mut session,
                    &[&request[..split], &[], &request[split..]],
                    &mut store,
                    &mut crypto,
                    100
                ),
                0
            );
            assert_eq!(store.writes, 1);
            assert_eq!(&store.record[16..20], &[8, 6, 8, 18]); // force + two RPs
            assert_eq!(&store.record[20..52], &Sha256::digest("例".as_bytes())[..]);
            assert_eq!(&store.record[52..], &Sha256::digest([b'a'; 24])[..]);
            assert_eq!(session.permissions, 0); // raising minimum revokes token
        }
    }
}
#[test]
fn policy_is_monotonic_atomic_and_can_disable_always_uv_without_pin() {
    let mut session = Session::new();
    let mut store = Backend::default();
    let mut crypto = Backend::default();
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa1, 1, 2]],
            &mut store,
            &mut crypto,
            0
        ),
        0
    );
    assert_eq!(store.record.len(), 20);
    assert_eq!(store.record[19], pin::ALWAYS_UV);
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa1, 1, 4]],
            &mut store,
            &mut crypto,
            0
        ),
        0x36
    );
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa1, 1, 2]],
            &mut store,
            &mut crypto,
            0
        ),
        0
    );
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa2, 1, 3, 2, 0xa1, 3, 0xf5]],
            &mut store,
            &mut crypto,
            0
        ),
        0x35
    );
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa2, 1, 3, 2, 0xa1, 1, 8]],
            &mut store,
            &mut crypto,
            0
        ),
        0
    );
    let saved = store.record.clone();
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa2, 1, 3, 2, 0xa1, 1, 7]],
            &mut store,
            &mut crypto,
            0
        ),
        0x37
    );
    store.fail = true;
    session.permissions = 0x20;
    assert_eq!(
        run(
            &mut session,
            &[&[13, 0xa1, 1, 4]],
            &mut store,
            &mut crypto,
            0
        ),
        0x7f
    );
    assert_eq!(store.record, saved);
    assert_eq!(session.permissions, 0);
}
#[test]
fn rejected_auth_never_writes_or_refreshes_and_success_refreshes_idle_only() {
    let mut message = vec![0xff; 32];
    message.extend_from_slice(&[13, 2]);
    for protocol in [1, 2] {
        let mut request = vec![13, 0xa3, 1, 2, 3, protocol, 4];
        let n = if protocol == 1 {
            request.push(0x50);
            16
        } else {
            request.extend_from_slice(&[0x58, 32]);
            32
        };
        request.extend_from_slice(&vec![0x5a; n]);
        for (permissions, now, valid_mac, expected) in [
            (3, 100, true, 0x33),
            (0x20, 30000, true, 0x33),
            (0x20, 100, false, 0x33),
            (0x20, 29999, true, 0),
        ] {
            let mut session = Session::new();
            session.permissions = permissions;
            session.token.fill(7);
            let mut store = Backend {
                record: vec![0; 20],
                ..Backend::default()
            };
            store.record[16..20].copy_from_slice(&[8, 8, 4, 0]);
            let mut crypto = Backend {
                expected_message: message.clone(),
                ..Backend::default()
            };
            let mut req = request.clone();
            if !valid_mac {
                *req.last_mut().unwrap() ^= 1;
            }
            assert_eq!(
                run(&mut session, &[&req], &mut store, &mut crypto, now),
                expected
            );
            assert_eq!(store.writes, usize::from(expected == 0));
            assert_eq!(session.token_used, if expected == 0 { now } else { 0 });
            assert_eq!(session.token_started, 0);
        }
    }
}
#[test]
fn forced_pin_change_blocks_both_tokens_and_clears_atomically_on_valid_change() {
    use super::super::client_pin;
    let old_hash = Sha256::digest(b"12345678");
    let mut record = vec![0; 52];
    record[..16].copy_from_slice(&old_hash[..16]);
    record[16..20].copy_from_slice(&[8, 8, 10, pin::FORCE_CHANGE | 8]);
    record[20..].fill(0xaa);
    let mut store = Backend {
        record,
        ..Backend::default()
    };
    let mut session = Session::new();
    session.agreement_ready = true;
    for (subcommand, new_pin, expected) in [
        (5, "", 0x31), // CTAP2_ERR_PIN_INVALID
        (9, "", 0x37), // CTAP2_ERR_PIN_POLICY_VIOLATION
        (4, "12345679", 0x37),
        (4, "1234567890", 0),
    ] {
        let mut cp = client_pin::Parameters {
            protocol: 1,
            subcommand,
            agreement: [0; 64],
            auth: [0x5a; 32],
            new_pin: [0; 80],
            pin_hash: [0; 32],
            permissions: 0x20,
            rp: [0; 254],
            rp_len: 0,
        };
        cp.new_pin[..new_pin.len()].copy_from_slice(new_pin.as_bytes());
        cp.pin_hash[..16].copy_from_slice(&old_hash[..16]);
        let mut crypto = Backend {
            expected_key: Some(Sha256::digest([7; 32]).into()),
            expected_message: [&cp.new_pin[..64], &cp.pin_hash[..16]].concat(),
            ..Backend::default()
        };
        let mut w = Workspace::new();
        let result = session.client_pin(
            &mut cp,
            &mut w,
            &mut Platform {
                storage: &mut store,
                crypto: &mut crypto,
                device: &mut Backend::default(),
                memory: &Backend::default(),
            },
        );
        assert_eq!(result.err().map_or(0, |s| s as u8), expected);
        assert_eq!(store.record[16], 8);
        assert_eq!(store.record[18], 10);
        assert_eq!(
            store.record[19],
            8 | if expected == 0 { 0 } else { pin::FORCE_CHANGE }
        );
        assert_eq!(&store.record[20..], &[0xaa; 32]);
    }
    assert_eq!(store.record[17], 10);
    assert_eq!(&store.record[..16], &Sha256::digest(b"1234567890")[..16]);
}
#[test]
fn malformed_config_has_no_persistent_effects() {
    let cases: &[(&[u8], u8)] = &[
        (&[13], 0xf1),
        (&[13, 0xa1], 0x12),
        (&[13, 0xa0], 0x14),
        (&[13, 0xa1, 1, 1], 2),
        (&[13, 0xa2, 1, 3, 2, 0xa1, 1, 0x18, 64], 2),
        (
            &[
                13, 0xa2, 1, 3, 2, 0xa1, 2, 0x85, 0x60, 0x60, 0x60, 0x60, 0x60,
            ],
            0x28,
        ),
        (&[13, 0xa2, 1, 3, 2, 0xa1, 2, 0x81, 0x40], 0x11),
        (&[13, 0xa2, 1, 3, 2, 0xa2, 1, 4, 1, 5], 0x12),
        (&[13, 0xa2, 1, 3, 2, 0xa2, 3, 0xf4, 1, 5], 0x12),
        (&[13, 0xa2, 1, 3, 2, 0xa1, 2, 0x81, 0x61, 0xff], 0x12),
    ];
    for &(request, status) in cases {
        let mut store = Backend::default();
        assert_eq!(
            run(
                &mut Session::new(),
                &request.chunks(1).collect::<Vec<_>>(),
                &mut store,
                &mut Backend::default(),
                0
            ),
            status,
            "{request:x?}"
        );
        assert_eq!(store.writes, 0);
    }
}

#[test]
fn token_authorization_refresh_and_expiry_follow_successful_uses_across_wrap() {
    for protocol in [1, 2] {
        for start in [0u32, u32::MAX - 10_000] {
            for invalid_attempt in [false, true] {
                let mut session = Session::new();
                session.token.fill(7);
                session.permissions = pin::PERMISSION_CONFIG;
                session.token_started = start;
                session.token_used = start;
                let mut store = Backend::default();
                let mut crypto = Backend {
                    expected_message: vec![1, 2, 3],
                    ..Backend::default()
                };
                let mut device = Backend::default();
                let memory = Backend::default();
                let mut authorize = |session: &mut Session, elapsed: u32, valid: bool| {
                    device.now = start.wrapping_add(elapsed);
                    let auth = [if valid { 0x5a } else { 0 }; 32];
                    session.authorize(
                        protocol,
                        &auth[..if protocol == 1 { 16 } else { 32 }],
                        &[1, 2, 3],
                        pin::PERMISSION_CONFIG,
                        None,
                        &mut Platform {
                            storage: &mut store,
                            crypto: &mut crypto,
                            device: &mut device,
                            memory: &memory,
                        },
                    )
                };
                if invalid_attempt {
                    assert_eq!(
                        authorize(&mut session, 20_000, false),
                        Err(Status::PinAuthInvalid)
                    );
                    assert_eq!(session.token_used, start);
                    assert_eq!(
                        authorize(&mut session, 30_001, true),
                        Err(Status::PinAuthInvalid)
                    );
                } else {
                    for elapsed in (29_000..600_000).step_by(29_000) {
                        assert_eq!(authorize(&mut session, elapsed, true), Ok(()));
                        assert_eq!(session.token_used, start.wrapping_add(elapsed));
                        assert_eq!(session.token_started, start);
                    }
                    assert_eq!(
                        authorize(&mut session, 600_000, true),
                        Err(Status::PinAuthInvalid)
                    );
                }
                assert_eq!(session.permissions, 0);
                assert_eq!(session.token, [0; 32]);
                assert_eq!(store.writes, 0);
            }
        }
    }
}
