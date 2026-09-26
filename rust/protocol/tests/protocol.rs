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
    let mut offset = 0;
    for (length, sw) in [(254, 0x61ff), (254, 0x6104), (4, 0x9000)] {
        let chunk = ResponsePlan::new(512, offset, 254, StatusWord::SUCCESS).unwrap();
        assert_eq!(
            (chunk.length, chunk.sw),
            (length, StatusWord::new(sw).unwrap())
        );
        offset = chunk.next;
    }
    assert_eq!(offset, 512);
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

#[test]
fn changed_chain_header_discards_previous_command_and_overflow_recovers() {
    let first = [0x90, 0x01, 0x02, 0x03, 0x02, 0xaa, 0xbb];
    for field in 0..4 {
        for chained in [false, true] {
            let mut chain = apdu::CommandChain::new();
            let original = apdu::parse(&first).unwrap().info;
            assert!(!chain.accept(original, 4).unwrap().last);
            let mut changed = first;
            changed[field] ^= 1;
            if !chained {
                changed[0] &= !0x10;
            }
            let next = apdu::parse(&changed).unwrap().info;
            let step = chain.accept(next, 2).unwrap();
            assert!(step.restarted); // Old bytes must not count toward this limit.
            assert_eq!(step.last, !chained);
            if chained {
                let mut last = changed;
                last[0] &= !0x10;
                let step = chain.accept(apdu::parse(&last).unwrap().info, 4).unwrap();
                assert!(!step.restarted && step.last);
            }
            assert!(!chain.active());
            chain.accept(original, 2).unwrap();
            assert_eq!(chain.accept(original, 2), Err(apdu::Error::Length));
            assert!(!chain.active());
            assert!(chain.accept(original, 2).unwrap().restarted);
        }
    }
}

#[test]
fn der_signature_preserves_coordinates_across_overlapping_moves() {
    use canokey_protocol::der::der_signature;
    // Exercise every supported width, leading-zero count and sign-padding
    // combination, including the DER sequence's 127/128-byte boundary.
    for width in 1..=66 {
        for r_skip in 0..width {
            for s_skip in 0..width {
                for sign_bits in 0..4 {
                    let mut raw = vec![0; width * 2];
                    let mut body = Vec::new();
                    for (i, skip) in [r_skip, s_skip].into_iter().enumerate() {
                        let negative = sign_bits & (1 << i) != 0;
                        let value = &mut raw[i * width + skip..(i + 1) * width];
                        value.fill(if negative { 0x80 } else { 0x01 });
                        body.extend([2, (value.len() + usize::from(negative)) as u8]);
                        if negative {
                            body.push(0);
                        }
                        body.extend_from_slice(value);
                    }
                    let mut expected = vec![0x30];
                    if body.len() >= 128 {
                        expected.push(0x81);
                    }
                    expected.push(body.len() as u8);
                    expected.extend(body);
                    raw.resize(width * 2 + 9, 0xa5);
                    let n = der_signature(&mut raw, width * 2).unwrap();
                    assert_eq!(&raw[..n], expected);
                }
            }
        }
        let mut zeros = vec![0; width * 2 + 9];
        let n = der_signature(&mut zeros, width * 2).unwrap();
        assert_eq!(&zeros[..n], &[0x30, 6, 2, 1, 0, 2, 1, 0]);
    }
    for (len, n) in [(9, 0), (10, 1), (142, 134), (72, 64)] {
        let mut out = vec![0xa5; len];
        assert!(der_signature(&mut out, n).is_err());
        assert!(out.iter().all(|b| *b == 0xa5));
    }
}
