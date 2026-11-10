// SPDX-License-Identifier: Apache-2.0
// Preserve the frozen differential projection byte-for-byte.
#[rustfmt::skip]
#[path = "fixtures/stage_80a497b4.rs"]
mod before;
use canokey_ctap::{
    ports::CertificateStage,
    provision::{Certificate, StageError},
};

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Stage {
    fail: bool,
    calls: Vec<(u8, usize)>,
    pending: usize,
    committed: usize,
}
impl Stage {
    fn call(&mut self, operation: u8, length: usize) -> Result<(), u8> {
        self.calls.push((operation, length));
        if self.fail { Err(0x42) } else { Ok(()) }
    }
}
impl CertificateStage for Stage {
    type Error = u8;
    fn begin(&mut self) -> Result<(), u8> {
        self.call(0x01, 0)?;
        self.pending = 0;
        Ok(())
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), u8> {
        self.call(0x02, bytes.len())?;
        self.pending += bytes.len();
        Ok(())
    }
    fn commit(&mut self) -> Result<(), u8> {
        self.call(0x03, 0)?;
        self.committed = self.pending;
        self.pending = 0;
        Ok(())
    }
    fn abort(&mut self) {
        self.calls.push((0x04, 0));
        self.pending = 0;
    }
}
fn error(value: StageError<u8>) -> before::Error {
    match value {
        StageError::Source(code) => {
            assert_eq!(code, 0x42);
            before::Error::Storage
        }
        StageError::Length => before::Error::Length,
        StageError::NotActive => before::Error::NotActive,
    }
}
#[test]
fn publication_latch_counter_and_all_backend_calls_match_fixed_core_traces() {
    const EVENTS: usize = 13;
    let bytes = [0x37; before::CERT_LIMIT + 1];
    let mut transitions = 0;
    for initial_used in [0, before::CERT_LIMIT - 1, before::CERT_LIMIT, usize::MAX] {
        for trace in 0..EVENTS.pow(4) {
            let mut old = before::Certificate::new();
            let mut new = Certificate::new();
            let mut expected = Stage::default();
            let mut actual = expected.clone();
            let mut old_used = initial_used;
            let mut new_used = initial_used;
            let mut rest = trace;
            for _ in 0..4 {
                let event = rest % EVENTS;
                rest /= EVENTS;
                expected.fail = event % 2 != 0;
                actual.fail = expected.fail;
                let mut platform = before::Platform {
                    storage: &mut expected,
                };
                let (left, right) = match event {
                    0..=1 => (old.begin(&mut platform), new.begin(&mut actual)),
                    2..=9 => {
                        let length =
                            [0, 1, before::CERT_LIMIT, before::CERT_LIMIT + 1][(event - 2) / 2];
                        (
                            old.append(&mut old_used, &bytes[..length], &mut platform),
                            new.append(
                                &mut new_used,
                                &bytes[..length],
                                before::CERT_LIMIT,
                                &mut actual,
                            ),
                        )
                    }
                    10..=11 => (old.commit(&mut platform), new.commit(&mut actual)),
                    _ => {
                        old.abort(&mut platform);
                        new.abort(&mut actual);
                        (Ok(()), Ok(()))
                    }
                };
                assert_eq!(left, right.map_err(error));
                assert_eq!(old.active(), new.active());
                assert_eq!(old_used, new_used);
                assert_eq!(expected, actual);
                transitions += 1;
            }
        }
    }
    assert_eq!(transitions, 456976);
}
