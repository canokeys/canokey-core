// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn prepaid_attempts_preserve_status_and_write_sequence() {
    for input in [&b"a"[..], b"b", b"", b"ab"] {
        for remaining in 1..=3 {
            let mut bytes = [remaining, b'a'];
            let mut writes = [0; 2];
            let mut count = 0;
            let result = Credential::new(&mut bytes, 1..2, 0, 3)
                .unwrap()
                .verify(input, &mut |b| {
                    writes[count] = b[0];
                    count += 1;
                    Ok(())
                });
            let (expected, sequence): (_, &[u8]) = if input == b"a" {
                (Ok(()), &[remaining - 1, 3])
            } else {
                let retry = if remaining == 1 {
                    Error::Blocked
                } else {
                    Error::Retries(remaining - 1)
                };
                (Err(retry), &[remaining - 1])
            };
            assert_eq!(result, expected);
            assert_eq!(&writes[..count], sequence);
        }
    }
}

#[test]
fn failed_decrement_never_compares() {
    let mut bytes = [2, b'a'];
    assert_eq!(
        Credential::new(&mut bytes, 1..2, 0, 3)
            .unwrap()
            .verify_with(
                b"a",
                &mut |record| {
                    assert_eq!(record[0], 1);
                    Err(Error::Persistence)
                },
                |_, _| panic!("compared before committing the attempt"),
            ),
        Err(Error::Persistence)
    );
}

#[test]
fn mismatch_is_compared_after_committing_decrement() {
    use core::cell::Cell;

    let mut bytes = [2, b'a'];
    let committed = Cell::new(false);
    assert_eq!(
        Credential::new(&mut bytes, 1..2, 0, 3)
            .unwrap()
            .verify_with(
                b"b",
                &mut |record| {
                    assert!(!committed.replace(true));
                    assert_eq!(record[0], 1);
                    Ok(())
                },
                |input, stored| {
                    assert!(committed.get());
                    super::super::equal(input, stored)
                },
            ),
        Err(Error::Retries(1))
    );
}

#[test]
fn failed_restore_never_succeeds() {
    for commit_on_error in [false, true] {
        let mut bytes = [2, b'a'];
        let mut durable = bytes;
        let mut calls = 0;
        let result = Credential::new(&mut bytes, 1..2, 0, 3)
            .unwrap()
            .verify(b"a", &mut |record| {
                calls += 1;
                if calls == 1 || commit_on_error {
                    durable.copy_from_slice(record);
                }
                if calls == 2 {
                    Err(Error::Persistence)
                } else {
                    Ok(())
                }
            });
        assert_eq!(calls, 2);
        assert_eq!(result, Err(Error::Persistence));
        assert_eq!(durable[0], if commit_on_error { 3 } else { 1 });
    }
}

#[test]
fn blocked_and_invalid_records_cannot_commit() {
    let mut bytes = [0x00, b'a'];
    assert_eq!(
        Credential::new(&mut bytes, 1..2, 0, 3)
            .unwrap()
            .verify(b"a", &mut |_| panic!("blocked credential wrote storage")),
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
        fail_write: bool,
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
                fail_write: false,
                id: 0,
            }
        }
    }
    impl Storage for Store {
        fn replace_at(
            &mut self,
            id: Record,
            offset: u32,
            input: &[u8],
        ) -> Result<(), StorageError> {
            assert_eq!(id.id(), self.id);
            assert_eq!(offset, 2);
            assert!((1..=2).contains(&input.len()));
            self.writes += 1;
            if self.unavailable || self.fail_write {
                return Err(StorageError::Uncertain);
            }
            assert!(self.exists);
            self.value[offset as usize..offset as usize + input.len()].copy_from_slice(input);
            Ok(())
        }
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
            if self.unavailable || self.fail_write {
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
            Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
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
            pin.verify(b"xxxxxx", 6, &mut platform!(&mut store, &memory)),
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
            pin.verify(b"abcdef", 6, &mut platform!(&mut store, &memory)),
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
    #[cfg(feature = "openpgp")]
    #[test]
    fn record_lifecycle_blocking_and_storage_errors() {
        let pin = RecordPin {
            id: Record::PgpRc,
            stored_min: 0,
            fixed_limit: None,
        };
        let mut store = Store::default();
        let memory = Eraser::default();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        assert_eq!(
            pin.verify(b"1234", 4, &mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        store.unavailable = true;
        assert_eq!(
            pin.create(b"1234", 3, &mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        store.unavailable = false;
        pin.create(b"1234", 3, &mut platform!(&mut store, &memory))
            .unwrap();
        let writes = store.writes;
        for value in [&b"12"[..], &[0; 65][..]] {
            assert_eq!(
                pin.verify(value, 4, &mut platform!(&mut store, &memory)),
                Err(Error::Length)
            );
            assert_eq!(
                pin.change(value, 4, &mut platform!(&mut store, &memory)),
                Err(Error::Length)
            );
        }
        assert_eq!(store.writes, writes);
        for remaining in [2, 1, 0] {
            let result = pin.verify(b"0000", 4, &mut platform!(&mut store, &memory));
            assert_eq!(
                result,
                if remaining == 0 {
                    Err(Error::Blocked)
                } else {
                    Err(Error::Retries(remaining))
                }
            );
            assert_eq!(
                pin.info(&mut platform!(&mut store, &memory))
                    .unwrap()
                    .retries_remaining,
                remaining
            );
        }
        let writes = store.writes;
        assert_eq!(
            pin.verify(b"1234", 4, &mut platform!(&mut store, &memory)),
            Err(Error::Blocked)
        );
        assert_eq!(store.writes, writes);
        pin.retry_limit(15, &mut platform!(&mut store, &memory))
            .unwrap();
        pin.change(b"5678", 4, &mut platform!(&mut store, &memory))
            .unwrap();
        pin.verify(b"5678", 4, &mut platform!(&mut store, &memory))
            .unwrap();
        let info = pin.info(&mut platform!(&mut store, &memory)).unwrap();
        assert_eq!(
            (info.length_bytes, info.retries_remaining, info.retry_limit),
            (4, 15, 15)
        );
        // Disabled OpenPGP reset codes retain policy, but cannot authenticate.
        pin.change(b"", 0, &mut platform!(&mut store, &memory))
            .unwrap();
        pin.retry_limit(5, &mut platform!(&mut store, &memory))
            .unwrap();
        assert_eq!(
            pin.info(&mut platform!(&mut store, &memory)),
            Ok(PinInfo {
                length_bytes: 0,
                retries_remaining: 0,
                retry_limit: 5,
            })
        );
        assert_eq!(
            pin.verify(b"", 0, &mut platform!(&mut store, &memory)),
            Err(Error::Blocked)
        );
    }

    #[cfg(feature = "openpgp")]
    #[test]
    fn record_mutations_require_an_existing_credential() {
        let pin = RecordPin {
            id: Record::PgpRc,
            stored_min: 0,
            fixed_limit: None,
        };
        let mut store = Store::default();
        let memory = Eraser::default();
        for value in [&b""[..], b"5678"] {
            assert_eq!(
                pin.change(value, 0, &mut platform!(&mut store, &memory)),
                Err(Error::Persistence)
            );
        }
        assert_eq!(
            pin.retry_limit(3, &mut platform!(&mut store, &memory)),
            Err(Error::Persistence)
        );
        assert!(!store.exists);
        assert_eq!(store.writes, 0);
    }

    #[cfg(feature = "admin")]
    #[test]
    fn admin_failed_decrement_revokes_grant_and_queries_durable_counter() {
        use crate::applets::admin::protocol::{Admin, Grants};
        use crate::runtime::workspace::Workspace;
        use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

        let memory = Eraser::default();
        let mut store = Store::default();
        let mut admin = Admin::new();
        admin.install(&mut platform!(&mut store, &memory)).unwrap();
        let mut grants = Grants { admin: true };
        let mut workspace = Workspace {
            key: &mut KeyMaterial::new(),
            #[cfg(feature = "piv")]
            agreement: &mut [0; crate::runtime::workspace::agreement_layout::SIZE],
            input: &mut [0; crate::runtime::workspace::INPUT_BYTES],
            output: &mut [0; crate::runtime::workspace::OUTPUT_BYTES],
        };
        let header = Header {
            cla: 0,
            ins: 0x20,
            p1: 0,
            p2: 0,
        };
        store.fail_write = true;
        let mut platform = platform!(&mut store, &memory);
        admin
            .consume(b"123456", &mut workspace, &mut platform)
            .unwrap();
        assert!(matches!(
            admin.finish(header, 0, &mut grants, None, &mut platform, &mut workspace),
            Err(Sw::UNABLE_TO_PROCESS)
        ));
        assert!(!grants.admin);
        assert_eq!(store.writes, 2);
        let durable = store.value[2];
        assert_eq!(durable, 3);
        store.fail_write = false;
        assert!(matches!(
            admin.finish(header, 0, &mut grants, None, &mut platform!(&mut store, &memory), &mut workspace),
            Err(sw) if sw == Sw::retries(durable)
        ));
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
        assert_eq!(store.writes, writes + 2);
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
    fn record_validation_precedes_comparison_and_retry_writes() {
        let pin = RecordPin {
            id: Record::PgpRc,
            stored_min: 0,
            fixed_limit: None,
        };
        let mut store = Store::default();
        let memory = Eraser::default();
        for (at, value) in [(0, 2), (1, 65), (2, 4), (3, 0), (1, 0)] {
            pin.create(b"1234", 3, &mut platform!(&mut store, &memory))
                .unwrap();
            store.value[at] = value;
            if at == 1 {
                // Also exercise a disabled PIN with an invalid live counter.
                store.length = 4 + value as usize;
                // An oversized record cannot be copied into the read buffer.
                if value == 65 {
                    store.length = 68;
                }
            }
            let writes = store.writes;
            let wipes = memory.0.get();
            assert_eq!(
                pin.verify(b"1234", 4, &mut platform!(&mut store, &memory)),
                Err(Error::Persistence)
            );
            assert_eq!(store.writes, writes);
            assert_eq!(memory.0.get(), wipes + 1);
        }
    }
}
