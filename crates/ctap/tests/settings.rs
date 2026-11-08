// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    ports::Sm2Settings,
    settings::{self, Sm2, WriteError},
};
use canokey_ports::StorageError;

mod before {
    include!("fixtures/settings_dcf88037.rs");
}

#[test]
fn codec_matches_fixed_product_snapshot_including_reserved_and_signed_boundaries() {
    assert_eq!(Sm2::DEFAULT.encode(), before::Sm2::DEFAULT.encode());
    for curve in (-512..=512).chain([i32::MIN, i32::MAX]) {
        for algorithm in (-128..=128).chain([i32::MIN, i32::MAX]) {
            let wire = Sm2 { curve, algorithm }.encode();
            assert_eq!(wire, before::Sm2 { curve, algorithm }.encode());
            let expected = before::Sm2::decode(&wire).map(|value| (value.curve, value.algorithm));
            let actual = Sm2::decode(&wire).map(|value| (value.curve, value.algorithm));
            assert_eq!(actual, expected);
        }
    }
    for length in 0..=16 {
        let bytes = [0xa5; 16];
        assert_eq!(
            Sm2::decode(&bytes[..length]).is_some(),
            before::Sm2::decode(&bytes[..length]).is_some()
        );
    }
}

struct Record {
    wire: [u8; settings::RECORD_BYTES],
    read: Result<usize, StorageError>,
    write: Result<(), StorageError>,
    loads: usize,
    replaces: usize,
}
impl Record {
    fn new() -> Self {
        Self {
            wire: Sm2::DEFAULT.encode(),
            read: Ok(settings::RECORD_BYTES),
            write: Ok(()),
            loads: 0,
            replaces: 0,
        }
    }
}
impl Sm2Settings for Record {
    fn load(&mut self, out: &mut [u8; settings::RECORD_BYTES]) -> Result<usize, StorageError> {
        self.loads += 1;
        out.copy_from_slice(&self.wire);
        self.read
    }
    fn replace(&mut self, wire: &[u8]) -> Result<(), StorageError> {
        self.replaces += 1;
        assert_eq!(wire.len(), settings::RECORD_BYTES);
        if self.write.is_ok() {
            self.wire.copy_from_slice(wire);
        }
        self.write
    }
}

#[test]
fn missing_is_default_but_short_malformed_and_io_errors_are_not() {
    for outcome in [
        Err(StorageError::Missing),
        Err(StorageError::Unavailable),
        Ok(0),
        Ok(7),
        Ok(8),
        Ok(9),
    ] {
        for malformed in [false, true] {
            let mut source = Record::new();
            source.read = outcome;
            if malformed {
                source.wire = Sm2 {
                    curve: 1,
                    algorithm: -7,
                }
                .encode();
            }
            let result = settings::load(&mut source);
            assert_eq!(
                result.is_ok(),
                outcome == Err(StorageError::Missing) || (outcome == Ok(8) && !malformed)
            );
            if let Ok(value) = result {
                assert_eq!(value, Sm2::DEFAULT);
            }
            assert_eq!((source.loads, source.replaces), (1, 0));
        }
    }
}

#[test]
fn invalid_provisioning_never_reaches_storage_and_write_failure_keeps_old_record() {
    for length in 0..=16 {
        if length == settings::RECORD_BYTES {
            continue;
        }
        let mut target = Record::new();
        assert_eq!(
            settings::save(&[0xa5; 16][..length], &mut target),
            Err(WriteError::Length)
        );
        assert_eq!((target.loads, target.replaces), (0, 0));
    }
    for value in [
        Sm2 {
            curve: 1,
            algorithm: -54,
        },
        Sm2 {
            curve: 9,
            algorithm: -7,
        },
        Sm2 {
            curve: 9,
            algorithm: -48,
        },
    ] {
        let mut target = Record::new();
        assert_eq!(
            settings::save(&value.encode(), &mut target),
            Err(WriteError::Invalid)
        );
        assert_eq!((target.loads, target.replaces), (0, 0));
    }
    let custom = Sm2 {
        curve: 0x01020304,
        algorithm: -1234,
    };
    for error in [false, true] {
        let mut target = Record::new();
        if error {
            target.write = Err(StorageError::Unavailable);
        }
        assert_eq!(
            settings::save(&custom.encode(), &mut target),
            if error {
                Err(WriteError::Storage)
            } else {
                Ok(())
            }
        );
        assert_eq!((target.loads, target.replaces), (0, 1));
        assert_eq!(
            target.wire,
            if error {
                Sm2::DEFAULT.encode()
            } else {
                custom.encode()
            }
        );
    }
}
