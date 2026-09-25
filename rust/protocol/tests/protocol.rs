// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::{apdu, response::*, tlv};

#[test]
fn select_frame_in_two_transport_fragments() {
    let bytes = [0x00, 0xa4, 0x04, 0x00, 0x05, 0xf0, 0x00, 0x00, 0x00, 0x00];
    let command = apdu::parse(&bytes).unwrap();
    assert_eq!(command.data, [0xf0, 0x00, 0x00, 0x00, 0x00]);
    let mut decoder = apdu::FrameDecoder::new(bytes.len()).unwrap();
    let mut data = Vec::new();
    for part in [&bytes[..7], &bytes[7..]] {
        decoder
            .feed(part, &mut |bytes| {
                data.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(decoder.finish().unwrap(), command.info);
    assert_eq!(data, command.data);
}

#[test]
fn response_in_two_chunks() {
    let first = ResponsePlan::new(6, 0, 4, StatusWord::SUCCESS).unwrap();
    assert_eq!(first.length, 4);
    assert_eq!(first.sw, StatusWord::new(0x6102).unwrap());
    let last = ResponsePlan::new(6, first.next, 4, StatusWord::SUCCESS).unwrap();
    assert_eq!(last.length, 2);
    assert_eq!(last.sw, StatusWord::SUCCESS);
    assert!(last.complete);
}

#[test]
fn tlv_value_spans_iso_command_chain_without_reassembly() {
    let fragments: [&[u8]; 4] = [
        &[0x10, 0x01, 0x00, 0x00, 0x02, 0x71, 0x82],
        &[0x10, 0x01, 0x00, 0x00, 0x02, 0x00, 0x04],
        &[0x10, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02],
        &[0x00, 0x01, 0x00, 0x00, 0x02, 0x03, 0x04],
    ];
    let mut chain = apdu::CommandChain::default();
    let mut decoder = tlv::Decoder::default();
    let mut values = Vec::new();
    for (index, fragment) in fragments.iter().enumerate() {
        let command = apdu::parse(fragment).unwrap();
        let step = chain.accept(command.info, 8).unwrap();
        if step.restarted {
            decoder = tlv::Decoder::default();
            values.clear();
        }
        decoder
            .feed(command.data, &mut |event| {
                if let tlv::Event::Value(bytes) = event {
                    values.extend_from_slice(bytes);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(step.last, index == 3);
        if step.last {
            core::mem::take(&mut decoder).finish().unwrap();
        }
    }
    assert_eq!(values, [0x01, 0x02, 0x03, 0x04]);
}
