// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    ports::Certificate,
    response::{self, ReadError, ReadMode},
};

struct Source {
    result: Result<usize, u8>,
    calls: usize,
    offset: u32,
    mode: ReadMode,
}
impl Certificate for Source {
    type Error = u8;
    fn read(&mut self, offset: u32, out: &mut [u8], mode: ReadMode) -> Result<usize, u8> {
        assert_eq!(offset, self.offset);
        assert_eq!(mode, self.mode);
        self.calls += 1;
        // A backend can have written provisional bytes even when it fails.
        out.fill(0x37);
        self.result
    }
}

#[test]
fn exact_and_partial_reads_preserve_counts_errors_offsets_and_caller_owned_output() {
    for mode in [ReadMode::Exact, ReadMode::Partial] {
        for offset in [0, 1, 1023, 1151, u32::MAX] {
            for capacity in [0, 1, 7, 32] {
                for result in [
                    Ok(0),
                    Ok(1),
                    Ok(7),
                    Ok(32),
                    Ok(33),
                    Ok(usize::MAX),
                    Err(0x42),
                ] {
                    let mut source = Source {
                        result,
                        calls: 0,
                        offset,
                        mode,
                    };
                    let mut out = [0xa5; 34];
                    let expected = match result {
                        Err(error) => Err(ReadError::Source(error)),
                        Ok(count)
                            if count > capacity
                                || (mode == ReadMode::Exact && count != capacity) =>
                        {
                            Err(ReadError::Length)
                        }
                        Ok(count) => Ok(count),
                    };
                    assert_eq!(
                        response::certificate(&mut source, offset, &mut out[1..1 + capacity], mode),
                        expected
                    );
                    assert_eq!(source.calls, 1);
                    assert_eq!(out[0], 0xa5);
                    assert!(out[1..1 + capacity].iter().all(|byte| *byte == 0x37));
                    assert!(out[1 + capacity..].iter().all(|byte| *byte == 0xa5));
                }
            }
        }
    }
}
