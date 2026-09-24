// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::cbor::{Decoder, Error, Event};

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
