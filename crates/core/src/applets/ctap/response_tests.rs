// SPDX-License-Identifier: Apache-2.0
use super::Response;
use crate::ports::{Record, Storage, StorageError};
use crate::runtime::workspace::SessionWorkspace;
use canokey_protocol::response::StatusWord as Sw;

// Two prefix bytes, four certificate bytes, two signature bytes. Distinct
// ranges make a skipped certificate or accidentally published suffix visible.
const ENCODED: [u8; 8] = [0x10, 0x11, 1, 2, 3, 4, 0x90, 0x91];
const POISON: u8 = 0xa5;
struct Certificate {
    returned: usize,
    calls: usize,
}
impl Storage for Certificate {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::Unavailable)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn read_some_at(
        &mut self,
        record: Record,
        offset: u32,
        out: &mut [u8],
    ) -> Result<usize, StorageError> {
        assert_eq!(record, Record::CtapCertificate);
        self.calls += 1;
        out.fill(POISON);
        for (byte, value) in out.iter_mut().take(self.returned).zip((offset as u8 + 1)..) {
            *byte = value;
        }
        // Deliberately allow an invalid excessive count to test the consumer.
        Ok(self.returned)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        if self.read_some_at(record, offset, out)? == out.len() {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
}

#[test]
fn certificate_progress_never_skips_or_publishes_the_unread_suffix() {
    let mut workspace = SessionWorkspace::new();
    let workspace = workspace.classic();
    workspace.output[..4].copy_from_slice(&[0x10, 0x11, 0x90, 0x91]);
    for registration in [false, true] {
        let response = Response::Authentication {
            registration,
            prefix: 2,
            auth: 0,
            certificate: Some((2, 4)),
            total: ENCODED.len(),
        };
        for partial in [false, true] {
            for offset in 0..=ENCODED.len() {
                for length in 0..=ENCODED.len() - offset {
                    let cert_start = offset.max(2);
                    let cert_end = (offset + length).min(6);
                    let requested = cert_end.saturating_sub(cert_start);
                    for returned in 0..=5 {
                        let mut storage = Certificate { returned, calls: 0 };
                        let mut out = [POISON; 10];
                        let result = response.read_window(
                            &workspace,
                            offset,
                            &mut out[1..1 + length],
                            &mut storage,
                            partial,
                        );
                        let expected = if requested == 0 || returned == requested {
                            Ok(length)
                        } else if returned > requested || !registration || !partial {
                            Err(Sw::UNABLE_TO_PROCESS)
                        } else {
                            Ok(cert_start - offset + returned)
                        };
                        assert_eq!(result, expected);
                        if let Ok(n) = result {
                            assert_eq!(&out[1..1 + n], &ENCODED[offset..offset + n]);
                        }
                        assert_eq!(storage.calls, usize::from(requested != 0));
                        assert_eq!(out[0], POISON);
                        assert!(out[1 + length..].iter().all(|&byte| byte == POISON));
                    }
                }
            }
        }
    }
}
