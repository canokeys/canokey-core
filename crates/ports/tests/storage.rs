// SPDX-License-Identifier: Apache-2.0
use canokey_ports::{Storage, StorageError, canokey::Record};

#[derive(Default)]
struct Fake {
    calls: Vec<&'static str>,
    fail: Option<usize>,
}
impl Fake {
    fn call(&mut self, name: &'static str) -> Result<(), StorageError> {
        self.calls.push(name);
        if self.fail == Some(self.calls.len()) {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
}
impl Storage for Fake {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::Missing)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn read_at(&mut self, _: Record, _: u32, output: &mut [u8]) -> Result<(), StorageError> {
        self.call("read")?;
        output.fill(0xA5);
        Ok(())
    }
    #[cfg(feature = "storage-staging")]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.call("begin")
    }
    #[cfg(feature = "storage-staging")]
    fn stage_append(&mut self, _: &[u8]) -> Result<(), StorageError> {
        self.call("append")
    }
    #[cfg(feature = "storage-staging")]
    fn stage_abort(&mut self) {
        self.calls.push("abort");
    }
}
#[test]
fn default_configuration_is_unprovisioned_and_cannot_persist_writes() {
    let mut io = Fake::default();
    assert_eq!(
        io.config_read(0, &mut [0x00; 8]),
        Err(StorageError::Missing)
    );
    assert_eq!(
        io.config_write(&[0x00; 512]),
        Err(StorageError::Unavailable)
    );
    assert!(io.calls.is_empty());
}
#[cfg(feature = "ctap")]
#[test]
fn prefix_fallback_exposes_only_a_completed_exact_window() {
    let mut io = Fake::default();
    let mut out = [0x00; 4];
    assert_eq!(io.read_some_at(Record::CtapCounter, 2, &mut out), Ok(4));
    assert_eq!(out, [0xA5; 4]);
    io.fail = Some(2);
    out.fill(0x00);
    assert_eq!(
        io.read_some_at(Record::CtapCounter, 2, &mut out),
        Err(StorageError::Uncertain)
    );
    assert_eq!(out, [0x00; 4]);
}
#[cfg(any(feature = "openpgp", feature = "piv", feature = "ctap"))]
#[test]
fn scatter_failure_aborts_once_and_never_attempts_later_parts() {
    let parts: &[&[u8]] = &[&[0x01], &[], &[0x02, 0x03]];
    for failure in 1..=4 {
        let mut io = Fake {
            fail: Some(failure),
            ..Fake::default()
        };
        assert_eq!(io.stage_parts(parts), Err(StorageError::Uncertain));
        assert_eq!(io.calls.len(), failure + 1);
        assert_eq!(io.calls.last(), Some(&"abort"));
    }
    let mut io = Fake::default();
    assert_eq!(io.stage_parts(parts), Ok(()));
    assert_eq!(io.calls, ["begin", "append", "append", "append"]);
    io.calls.clear();
    assert_eq!(io.stage_parts(&[]), Ok(()));
    assert_eq!(io.calls, ["begin"]);
}
