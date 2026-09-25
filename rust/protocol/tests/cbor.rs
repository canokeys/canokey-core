// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::cbor::{Decoder, Error, Event};

#[test]
fn bounded_encoder_canonical_wire_and_output_exhaustion() {
    use canokey_protocol::cbor::{EncodeError, Encoder};
    // RFC 8949 preferred integer widths, UTF-8 byte length and empty map.
    const EXPECTED: &[u8] = b"\x8c\x17\x19\x01\x00\x1a\x00\x01\x00\x00\x1b\xff\xff\xff\xff\xff\xff\xff\xff\x37\x39\x01\x00\x3a\x00\x01\x00\x00\x3b\x7f\xff\xff\xff\xff\xff\xff\xff\xf5\x42\x00\xff\x62\xc3\xa9\xa0";
    fn encode(e: &mut Encoder<&mut [u8]>) -> Result<(), EncodeError> {
        e.array(12)?
            .u8(23)?
            .u16(256)?
            .u32(65536)?
            .u64(u64::MAX)?
            .i8(-24)?
            .i16(-257)?
            .i32(-65537)?
            .i64(i64::MIN)?
            .bool(true)?
            .bytes(&[0, 255])?
            .str("é")?
            .map(0)?;
        Ok(())
    }
    for capacity in 0..=EXPECTED.len() {
        let mut guarded = [0xa5; 128];
        let mut e = Encoder::new(&mut guarded[1..1 + capacity]);
        if capacity == EXPECTED.len() {
            assert!(encode(&mut e).is_ok());
            assert_eq!(e.writer().len(), 0);
            assert_eq!(&guarded[1..1 + capacity], EXPECTED);
        } else {
            assert!(encode(&mut e).is_err(), "capacity {capacity}");
        }
        assert_eq!(guarded[0], 0xa5);
        assert!(guarded[1 + capacity..].iter().all(|b| *b == 0xa5));
    }
    // A streamed byte string writes its header without reserving its payload.
    let mut header = [0; 3];
    let mut e = Encoder::new(&mut header[..]);
    e.bytes_len(3309).unwrap();
    assert_eq!(e.writer().len(), 0);
    assert_eq!(header, [0x59, 0x0c, 0xed]);
}

#[test]
fn negative_argument_keeps_all_64_bits() {
    let wire = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    for split in 0..=wire.len() {
        assert_eq!(
            decode(&[&wire[..split], &wire[split..]], 9).unwrap(),
            ["Negative(18446744073709551615)"]
        );
    }
}

#[test]
fn slice_decoder_preserves_borrows_and_rejects_truncation() {
    use canokey_protocol::cbor::SliceDecoder;
    let input = b"\xa2\x01\x42ab\x02\x62\xc3\xa9";
    let mut d = SliceDecoder::new(input);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.u64().unwrap(), 1);
    let bytes = d.bytes().unwrap();
    assert_eq!(bytes, b"ab");
    assert_eq!(bytes.as_ptr(), input[3..].as_ptr());
    assert_eq!(d.u64().unwrap(), 2);
    assert_eq!(d.str().unwrap(), "é");
    assert!(d.skip().is_err());
    for n in 0..3 {
        assert!(SliceDecoder::new(&b"\x42ab"[..n]).bytes().is_err());
    }
    assert_eq!(SliceDecoder::new(&[0xf4]).bool().unwrap(), false);
    assert_eq!(SliceDecoder::new(&[0xf5]).bool().unwrap(), true);
    assert!(SliceDecoder::new(&[0xf6]).bool().is_err());
    assert!(SliceDecoder::new(&[0x61, 0xff]).str().is_err());
}

// Record semantic events without making USB fragment boundaries observable.
fn decode(parts: &[&[u8]], limit: u16) -> Result<Vec<String>, Error> {
    let mut decoder = Decoder::new(limit);
    let mut events = Vec::new();
    let mut body = None;
    for bytes in parts {
        decoder.feed(bytes, &mut |event| {
            match event {
                Event::Bytes(_) | Event::Text(_) => {
                    events.push(format!("{event:?}"));
                    body = Some(Vec::new());
                }
                Event::Data(bytes) => body.as_mut().unwrap().extend_from_slice(bytes),
                Event::End => {
                    if let Some(bytes) = body.take() {
                        events.push(format!("{bytes:?}"));
                    }
                    events.push("End".into());
                }
                _ => events.push(format!("{event:?}")),
            }
            Ok(())
        })?;
    }
    decoder.finish()?;
    Ok(events)
}

#[test]
fn minicbor_vectors_across_every_split() {
    // Library-generated vectors: large integers, nested collections, multibyte UTF-8,
    // strings crossing the short-buffer boundary, and empty containers/strings.
    let mut bytes = [0; 1024];
    let mut encoder = minicbor::Encoder::new(&mut bytes[..]);
    encoder
        .map(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .array(4)
        .unwrap()
        .u64(u64::MAX)
        .unwrap()
        .i64(i64::MIN)
        .unwrap()
        .bool(true)
        .unwrap()
        .null()
        .unwrap()
        .u8(2)
        .unwrap()
        .str("a\u{80}\u{800}\u{10000}\u{10ffff}")
        .unwrap()
        .u8(3)
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&[0x37; 256])
        .unwrap()
        .bytes(&[])
        .unwrap()
        .str("")
        .unwrap()
        .map(0)
        .unwrap();
    let n = 1024 - encoder.writer().len();
    let bytes = &bytes[..n];
    let expected = decode(&[bytes], n as u16).unwrap();
    assert_eq!(
        expected,
        [
            "Map(3)".into(),
            "Unsigned(1)".into(),
            "Array(4)".into(),
            "Unsigned(18446744073709551615)".into(),
            "Negative(9223372036854775807)".into(),
            "Bool(true)".into(),
            "Null".into(),
            "End".into(),
            "Unsigned(2)".into(),
            "Text(14)".into(),
            format!("{:?}", "a\u{80}\u{800}\u{10000}\u{10ffff}".as_bytes()),
            "End".into(),
            "Unsigned(3)".into(),
            "Array(4)".into(),
            "Bytes(256)".into(),
            format!("{:?}", [0x37u8; 256]),
            "End".into(),
            "Bytes(0)".into(),
            "[]".into(),
            "End".into(),
            "Text(0)".into(),
            "[]".into(),
            "End".into(),
            "Map(0)".into(),
            "End".into(),
            "End".into(),
            "End".into(),
        ]
    );
    for split in 0..=n {
        assert_eq!(
            decode(&[&bytes[..split], &bytes[split..]], n as u16).unwrap(),
            expected
        );
    }
    let fragments: Vec<_> = bytes.chunks(1).collect();
    assert_eq!(decode(&fragments, n as u16).unwrap(), expected);
    for length in 0..n {
        assert!(
            decode(&[&bytes[..length]], n as u16).is_err(),
            "prefix {length}"
        );
    }
    assert_eq!(decode(&[bytes], n as u16 - 1), Err(Error::Limit));
}

#[test]
fn reject_noncanonical_unsupported_invalid_text_and_trailing_values() {
    let invalid: &[&[u8]] = &[
        &[0x18, 0x17],
        &[0x19, 0, 0xff],
        &[0x1a, 0, 0, 0xff, 0xff],
        &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[0x58, 0],
        &[0x9f, 0xff],
        &[0xc0, 0],
        &[0xf9, 0, 0],
        &[0xf8, 20],
        &[0xff],
        &[0, 1],
        &[0x61, 0x80],
        &[0x62, 0xc0, 0x80],
        &[0x62, 0xc2, 0x7f],
        &[0x63, 0xe0, 0x9f, 0xbf],
        &[0x63, 0xed, 0xa0, 0x80],
        &[0x64, 0xf4, 0x90, 0x80, 0x80],
        &[0x61, 0xc2],
    ];
    for &bytes in invalid {
        for split in 0..=bytes.len() {
            assert!(
                decode(&[&bytes[..split], &bytes[split..]], 1024).is_err(),
                "{bytes:x?}"
            );
        }
    }
    assert_eq!(decode(&[&[0xa1, 0]], 1024), Err(Error::Truncated));
    assert_eq!(decode(&[&[0x5a, 0, 1, 0, 0]], 1024), Err(Error::Limit));
    let mut nested = vec![0x81; 8];
    nested.push(0);
    assert!(decode(&[&nested], 1024).is_ok());
    nested.insert(0, 0x81);
    assert_eq!(decode(&[&nested], 1024), Err(Error::Limit));
}

#[test]
fn consumer_failure_is_terminal() {
    let mut decoder = Decoder::new(1024);
    assert_eq!(
        decoder.feed(&[0xa1], &mut |_| Err(Error::Invalid)),
        Err(Error::Consumer)
    );
    assert_eq!(decoder.feed(&[0, 0], &mut |_| Ok(())), Err(Error::Failed));
    assert_eq!(decoder.finish(), Err(Error::Failed));
}
