// SPDX-License-Identifier: Apache-2.0
//! Shared incremental request framing and first-error handling. Command schemas
//! own field interpretation; this boundary preserves their exact status codes.
use super::Status;
use canokey_protocol::cbor::{self, Event};

pub(super) struct RequestDecoder {
    decoder: cbor::Decoder,
    error: Option<Status>,
}

impl RequestDecoder {
    pub const fn new() -> Self {
        Self {
            decoder: cbor::Decoder::new((super::MAX_REQUEST - 1) as u16),
            error: None,
        }
    }

    pub const fn large_blob() -> Self {
        Self {
            decoder: cbor::Decoder::new((super::MAX_REQUEST - 1) as u16).with_wide_byte_lengths(),
            error: None,
        }
    }

    /// Returns false after any failure. A rejected request never re-enters its
    /// schema, and a schema error takes precedence over the generic CBOR error.
    #[inline(never)]
    pub fn consume(
        &mut self,
        bytes: &[u8],
        fields: &mut dyn FnMut(Event<'_>, u16) -> Result<(), Status>,
    ) -> bool {
        if self.error.is_some() {
            return false;
        }
        let mut input = bytes;
        loop {
            match self.decoder.next_event(&mut input) {
                Ok(Some(event)) => {
                    if let Err(status) = fields(event, self.decoder.position()) {
                        self.error = Some(status);
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.error = Some(Status::InvalidCbor);
                    break;
                }
            }
        }
        self.error.is_none()
    }

    pub fn finish(&self) -> Result<(), Status> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.decoder.finish().map_err(|_| Status::InvalidCbor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_schema_error_survives_later_input() {
        let mut decoder = RequestDecoder::new();
        assert!(!decoder.consume(&[0xa0], &mut |_, _| Err(Status::InvalidParameter)));
        assert!(!decoder.consume(&[0xff], &mut |_, _| panic!("failed schema called again")));
        assert_eq!(decoder.finish(), Err(Status::InvalidParameter));
    }

    #[test]
    fn incomplete_or_malformed_cbor_cannot_finish() {
        for bytes in [&[0xa1, 0x01][..], &[0xff][..], &[0xa0, 0x00][..]] {
            let mut decoder = RequestDecoder::new();
            decoder.consume(bytes, &mut |_, _| Ok(()));
            assert_eq!(decoder.finish(), Err(Status::InvalidCbor));
        }
    }

    #[test]
    fn offsets_span_fragments_including_empty_containers() {
        let input = [0xa1, 0x01, 0x42, 0x12, 0x34];
        for split in 0..=input.len() {
            let mut decoder = RequestDecoder::new();
            let mut ends = [0; 2];
            let mut count = 0;
            let mut fields = |event: Event<'_>, offset: u16| {
                if matches!(event, Event::End) {
                    ends[count] = offset;
                    count += 1;
                }
                Ok(())
            };
            assert!(decoder.consume(&input[..split], &mut fields));
            assert!(decoder.consume(&input[split..], &mut fields));
            assert_eq!(decoder.finish(), Ok(()));
            assert_eq!(ends, [5, 5]);
        }
        let mut decoder = RequestDecoder::new();
        let mut closed = false;
        assert!(decoder.consume(&[0xa0], &mut |event, offset| {
            if matches!(event, Event::End) {
                assert_eq!(offset, 1);
                closed = true;
            }
            Ok(())
        }));
        assert!(closed);
        assert_eq!(decoder.finish(), Ok(()));
    }
}
