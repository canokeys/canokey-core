// SPDX-License-Identifier: Apache-2.0
//! Product request capacity for the shared first-error incremental decoder.
use super::Status;
pub(super) type RequestDecoder =
    canokey_ctap::request::stream::Decoder<Status, { (super::MAX_REQUEST - 1) as u16 }>;
#[cfg(test)]
mod tests {
    use super::*;
    use canokey_protocol::cbor::Event;

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
            let mut fields = |event: &Event<'_>, offset: u16| {
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
