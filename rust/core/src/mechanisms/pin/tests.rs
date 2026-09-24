// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn retry_policies_preserve_exact_write_sequences() {
    for (charge, prepaid) in [(Charge::OnMismatch, false), (Charge::BeforeCompare, true)] {
        for (input, correct) in [
            (&b"123456"[..], true),
            (&b"123457"[..], false),
            (&b"12345"[..], false),
            (&b"1234567"[..], false),
        ] {
            for remaining in 1..=3 {
                let mut bytes = [remaining, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
                bytes[1..].copy_from_slice(b"123456");
                let mut writes = [0; 2];
                let mut count = 0;
                let result = Credential::new(&mut bytes, 1..7, 0, 3).unwrap().verify(
                    input,
                    charge,
                    &mut |b| {
                        assert_eq!(&b[1..], b"123456");
                        writes[count] = b[0];
                        count += 1;
                        Ok(())
                    },
                );
                let expected = if correct {
                    Ok(())
                } else if remaining == 1 {
                    Err(Error::Blocked)
                } else {
                    Err(Error::Retries(remaining - 1))
                };
                assert_eq!(result, expected);
                let sequence: &[u8] = if correct && prepaid {
                    &[remaining - 1, 0x03]
                } else if correct && remaining != 3 {
                    &[3]
                } else if correct {
                    &[]
                } else {
                    &[remaining - 1]
                };
                assert_eq!(&writes[..count], sequence);
                assert_eq!(bytes[0], if correct { 3 } else { remaining - 1 });
            }
        }
    }
}

#[test]
fn no_success_after_any_failed_commit() {
    for charge in [Charge::OnMismatch, Charge::BeforeCompare] {
        for committed in [false, true] {
            for fail_at in 1..=2 {
                let mut bytes = [0x02, b'a'];
                let mut durable = bytes;
                let mut calls = 0;
                let result = Credential::new(&mut bytes, 1..2, 0, 3).unwrap().verify(
                    b"a",
                    charge,
                    &mut |b| {
                        calls += 1;
                        if calls != fail_at || committed {
                            durable.copy_from_slice(b);
                        }
                        if calls == fail_at {
                            Err(Error::Persistence)
                        } else {
                            Ok(())
                        }
                    },
                );
                if calls >= fail_at {
                    assert_eq!(result, Err(Error::Persistence));
                } else {
                    assert_eq!(result, Ok(()));
                }
                // The first prepaid write charges an attempt, never restores it.
                if matches!(charge, Charge::BeforeCompare) && fail_at == 1 {
                    assert_eq!(calls, 1);
                    assert_eq!(durable[0], if committed { 1 } else { 2 });
                }
            }
        }
    }
    // A failed attempt must also report a write failure, not a trusted counter.
    let mut bytes = [0x02, b'a'];
    assert_eq!(
        Credential::new(&mut bytes, 1..2, 0, 3).unwrap().verify(
            b"b",
            Charge::OnMismatch,
            &mut |_| Err(Error::Persistence)
        ),
        Err(Error::Persistence)
    );
}

#[test]
fn blocked_and_invalid_records_cannot_commit() {
    let mut bytes = [0x00, b'a'];
    assert_eq!(
        Credential::new(&mut bytes, 1..2, 0, 3).unwrap().verify(
            b"a",
            Charge::BeforeCompare,
            &mut |_| panic!("blocked credential wrote storage")
        ),
        Err(Error::Blocked)
    );
    for (range, counter, limit) in [(1..3, 0, 3), (1..2, 2, 3), (0..2, 0, 3), (1..2, 0, 0)] {
        assert!(Credential::new(&mut bytes, range, counter, limit).is_err());
    }
    bytes[0] = 4;
    assert!(Credential::new(&mut bytes, 1..2, 0, 3).is_err());
}

#[cfg(any(feature = "admin", feature = "openpgp"))]
mod records {
    use super::*;
    use crate::ports::*;
    use core::cell::Cell;
    struct Store {
        value: [u8; 68],
        length: usize,
        exists: bool,
        writes: usize,
        unavailable: bool,
        id: u8,
    }
    impl Default for Store {
        fn default() -> Self {
            Self {
                value: [0; 68],
                length: 0,
                exists: false,
                writes: 0,
                unavailable: false,
                id: 0,
            }
        }
    }
    impl Storage for Store {
        fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            if self.unavailable {
                return Err(StorageError::Unavailable);
            }
            if !self.exists {
                return Err(StorageError::Missing);
            }
            assert_eq!(id.id(), self.id);
            out[..self.length].copy_from_slice(&self.value[..self.length]);
            Ok(self.length)
        }
        fn replace(&mut self, id: Record, input: &[u8]) -> Result<(), StorageError> {
            self.writes += 1;
            if self.unavailable {
                return Err(StorageError::Uncertain);
            }
            self.id = id.id();
            self.exists = true;
            self.value.fill(0);
            self.length = input.len();
            self.value[..self.length].copy_from_slice(input);
            Ok(())
        }
    }
    struct Primitives;
    impl Crypto for Primitives {
        fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            unreachable!()
        }
    }
    struct Board;
    impl Device for Board {
        fn serial(&mut self, _: &mut [u8; 4]) {
            unreachable!()
        }
        fn now(&mut self) -> u32 {
            0
        }
        fn touched(&mut self) -> bool {
            false
        }
        fn progress(&mut self) -> bool {
            true
        }
        fn led(&mut self, _: bool) {}
    }
    #[derive(Default)]
    struct Eraser(Cell<usize>);
    impl Memory for Eraser {
        fn wipe(&self, b: &mut [u8]) {
            b.fill(0);
            self.0.set(self.0.get() + 1);
        }
    }
    macro_rules! platform {
        ($store:expr,$memory:expr) => {
            Platform {
                storage: $store,
                crypto: &mut Primitives,
                device: &mut Board,
                memory: $memory,
            }
        };
    }
    #[test]
    fn codec_replacement_and_cleanup_preserve_record_contract() {
        let pin = RecordPin {
            id: Record::PgpPw1,
            stored_min: 0,
            fixed_limit: None,
        };
        let mut store = Store::default();
        let memory = Eraser::default();
        pin.create(b"123456", 5, &mut platform!(&mut store, &memory))
            .unwrap();
        assert_eq!(store.length, 10);
        assert_eq!(&store.value[..10], b"\x01\x06\x05\x05123456");
        assert!(store.value[10..].iter().all(|b| *b == 0));
        assert_eq!(memory.0.get(), 1);
        assert_eq!(
            pin.verify(
                b"xxxxxx",
                6,
                Charge::OnMismatch,
                &mut platform!(&mut store, &memory)
            ),
            Err(Error::Retries(4))
        );
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(crate::mechanisms::pin::PinInfo {
                length_bytes: 6,
                retries_remaining: 4,
                retry_limit: 5
            })
        );
        pin.change(b"abcdef", 6, &mut platform!(&mut store, &memory))
            .unwrap();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(crate::mechanisms::pin::PinInfo {
                length_bytes: 6,
                retries_remaining: 5,
                retry_limit: 5
            })
        );
        let previous = store.value;
        assert_eq!(
            pin.create(&[1; 65], 5, &mut platform!(&mut store, &memory)),
            Err(Error::Length)
        );
        assert_eq!(store.value, previous);
        store.unavailable = true;
        let wiped = memory.0.get();
        assert_eq!(
            pin.verify(
                b"abcdef",
                6,
                Charge::OnMismatch,
                &mut platform!(&mut store, &memory)
            ),
            Err(Error::Persistence)
        );
        assert_eq!(memory.0.get(), wiped + 1);
        store.unavailable = false;
        store.value[0] = 2;
        let wiped = memory.0.get();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        assert_eq!(memory.0.get(), wiped + 1);
    }
    #[cfg(feature = "admin")]
    #[test]
    fn admin_keeps_length_precedence_and_fixed_retry_policy() {
        use crate::applets::admin::pin;
        let mut store = Store::default();
        let memory = Eraser::default();
        pin::install(&mut platform!(&mut store, &memory)).unwrap();
        let writes = store.writes;
        pin::verify(b"123456", &mut platform!(&mut store, &memory)).unwrap();
        assert_eq!(store.writes, writes);
        store.value[2] = 0;
        assert_eq!(
            pin::verify(b"bad", &mut platform!(&mut store, &memory)),
            Err(Error::Length)
        );
        assert_eq!(
            pin::verify(b"123456", &mut platform!(&mut store, &memory)),
            Err(Error::Blocked)
        );
        store.value[3] = 4;
        assert_eq!(
            pin::install(&mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        store.unavailable = true;
        assert_eq!(
            pin::verify(b"bad", &mut platform!(&mut store, &memory)),
            Err(Error::Length)
        );
    }
    #[cfg(feature = "openpgp")]
    #[test]
    fn openpgp_disabled_reset_code_and_prepaid_attempts() {
        let pin = RecordPin {
            id: Record::PgpRc,
            stored_min: 0,
            fixed_limit: None,
        };
        let mut store = Store::default();
        let memory = Eraser::default();
        pin.create(b"", 3, &mut platform!(&mut store, &memory))
            .unwrap();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(crate::mechanisms::pin::PinInfo {
                length_bytes: 0,
                retries_remaining: 0,
                retry_limit: 3
            })
        );
        assert_eq!(
            pin.verify(
                b"bad",
                8,
                Charge::BeforeCompare,
                &mut platform!(&mut store, &memory)
            ),
            Err(Error::Blocked)
        );
        pin.retry_limit(5, &mut platform!(&mut store, &memory))
            .unwrap();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(crate::mechanisms::pin::PinInfo {
                length_bytes: 0,
                retries_remaining: 0,
                retry_limit: 5
            })
        );
        pin.change(b"12345678", 8, &mut platform!(&mut store, &memory))
            .unwrap();
        let writes = store.writes;
        pin.verify(
            b"12345678",
            8,
            Charge::BeforeCompare,
            &mut platform!(&mut store, &memory),
        )
        .unwrap();
        assert_eq!(store.writes, writes + 2);
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(crate::mechanisms::pin::PinInfo {
                length_bytes: 8,
                retries_remaining: 5,
                retry_limit: 5
            })
        );
    }
}
