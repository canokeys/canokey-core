// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::resident::{self, Entry, FIELD_COUNT, FIXED_BYTES, ID_BYTES, MAX_BYTES};

#[path = "fixtures/resident_core_cd92e240.rs"]
mod core_reference;
#[path = "fixtures/resident_vlei_63470c9.rs"]
mod vlei_reference;

fn member(fields: &[&[u8]; FIELD_COUNT]) -> Vec<u8> {
    let mut bytes = vec![0x00; MAX_BYTES];
    bytes[1] = resident::RESIDENT;
    let written = resident::encode_fields(&mut bytes[FIXED_BYTES..], fields);
    bytes.truncate(FIXED_BYTES + written);
    bytes
}

fn compare(bytes: &[u8]) {
    let current = Entry::decode(bytes);
    let core = core_reference::Entry::decode(bytes);
    assert_eq!(current.is_ok(), core.is_ok(), "Core admission: {bytes:?}");
    assert_eq!(
        current.is_ok(),
        vlei_reference::validate(bytes).is_ok(),
        "vLEI admission: {bytes:?}"
    );
    if let (Ok(actual), Ok(expected)) = (current, core) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.rp_hash, expected.rp_hash);
        assert_eq!(actual.rp, expected.rp);
        assert_eq!(actual.user, expected.user);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.display, expected.display);
        assert_eq!(actual.blob, expected.blob);
        // Decoding lends the original backing; it must not create a second record.
        assert_eq!(actual.id.as_ptr(), bytes.as_ptr());
        assert_eq!(actual.rp_hash.as_ptr(), bytes[ID_BYTES..].as_ptr());
    }
}

#[test]
fn resident_codec_matches_both_fixed_product_decoders() {
    let maximal = member(&[
        &[b'r'; 32],
        &[0xff; 64],
        &[b'n'; 64],
        &[b'd'; 64],
        &[0xfe; 32],
    ]);
    let records = [
        member(&[b"r", b"\xff", "é".as_bytes(), "🔑".as_bytes(), b"\xfe"]),
        member(&[b"r", b"u", b"", b"", b""]),
        maximal,
    ];
    let mut cases = 0;
    for bytes in &records {
        compare(bytes);
        cases += 1;
        for length in 0..=bytes.len() {
            compare(&bytes[..length]);
            cases += 1;
        }
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        compare(&trailing);
        cases += 1;
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            for byte in 0x00..=0xff {
                changed[offset] = byte;
                compare(&changed);
                cases += 1;
            }
        }
    }
    println!("resident decoder differential cases: {cases}");
}

#[test]
fn resident_field_encoder_preserves_output_and_unused_backing() {
    for field in 0..FIELD_COUNT {
        for length in 0..=resident::FIELD_LIMITS[field] {
            let value = vec![b'x'; length];
            let mut fields: [&[u8]; FIELD_COUNT] = [b"r", b"u", b"", b"", b""];
            fields[field] = &value;
            let mut actual = [0xa5; MAX_BYTES];
            let mut expected = actual;
            let written = resident::encode_fields(&mut actual, &fields);
            let reference = core_reference::encode_fields(&mut expected, &fields);
            assert_eq!(written, reference);
            assert_eq!(actual, expected);
        }
    }
    assert_eq!(MAX_BYTES, 327);
    assert_eq!(resident::MIN_BYTES, 71);
}

#[test]
fn resident_text_and_rp_display_match_both_products_at_utf8_boundaries() {
    let mut cases = 0;
    for text in [
        "example.com",
        "界",
        "é🔑",
        "x://é🔑界",
        "verylongprotocolscheme://host.invalid",
    ] {
        for repeats in 0..=40 {
            let repeated = text.repeat(repeats);
            let bytes = repeated.as_bytes();
            for length in 0..=bytes.len() {
                let prefix = &bytes[..length];
                assert_eq!(
                    resident::text_prefix(prefix),
                    core_reference::text_prefix(prefix)
                );
                assert_eq!(
                    resident::text_prefix(prefix),
                    vlei_reference::text_prefix(prefix)
                );
            }
            // RP IDs admitted by either product are valid UTF-8. Compare full
            // scratch, not only the returned display, including unused bytes.
            let mut actual = [0xa5; 32];
            let mut core = actual;
            let mut vlei = actual;
            let display = resident::display_rp(bytes, &mut actual).to_vec();
            assert_eq!(display, core_reference::display_rp(bytes, &mut core));
            assert_eq!(display, vlei_reference::display_rp(bytes, &mut vlei));
            assert_eq!(actual, core);
            assert_eq!(actual, vlei);
            assert!(core::str::from_utf8(&display).is_ok());
            cases += 1;
        }
    }
    println!("resident RP display differential cases: {cases}");
}
