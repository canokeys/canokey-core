// SPDX-License-Identifier: Apache-2.0
extern crate std;

// Valid MC/GA requests vary one unknown integer label or one entity metadata
// field. Root labels follow CTAP integer ordering; entity keys are text ordered
// by encoded length and bytes. No product-only algorithms/extensions are used.
pub fn cases() -> std::vec::Vec<(bool, std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::{response::encoding::Encoder, status::Status};
    let mut cases = std::vec::Vec::new();
    // RFC 8949 major type 1: -1, -128 and -18446744073709551616;
    // followed by null. Text/byte-string labels have the wrong root key type.
    for label in [
        &b"\x20\xf6"[..],
        &b"\x38\x7f\xf6"[..],
        &b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff\xf6"[..],
        &b"\x61x\xf6"[..],
        &b"\x41x\xf6"[..],
    ] {
        for make in [false, true] {
            let mut wire = [0x00; 256];
            let mut e = Encoder::new(&mut wire[..]);
            e.map(if make { 5 } else { 3 });
            required(&mut e, make, None, None);
            e.finish().unwrap();
            let length = 256 - e.writer().len();
            let mut request = wire[..length].to_vec();
            request.extend_from_slice(label);
            let expected = (label[0] >> 5 != 0x01).then_some(Status::CborUnexpectedType as u8);
            cases.push((make, request, expected));
        }
    }
    for (user, key, requires_text) in [
        (false, "icon", true),
        (false, "name", true),
        (false, "displayName", true),
        (false, "other", true),
        (false, "unknown-label-longer-than-32-bytes!", true),
        (true, "icon", false),
        (true, "name", true),
        (true, "displayName", true),
        (true, "other", false),
        (true, "unknown-label-longer-than-32-bytes!", false),
    ] {
        for text in [false, true] {
            let mut wire = [0x00; 256];
            let mut e = Encoder::new(&mut wire[..]);
            e.map(4);
            let metadata = Some((key, text));
            required(
                &mut e,
                true,
                if user { None } else { metadata },
                if user { metadata } else { None },
            );
            e.finish().unwrap();
            let length = 256 - e.writer().len();
            cases.push((
                true,
                wire[..length].to_vec(),
                (requires_text && !text).then_some(Status::CborUnexpectedType as u8),
            ));
        }
    }
    cases
}

fn required(
    e: &mut canokey_ctap::response::encoding::Encoder<&mut [u8]>,
    make: bool,
    rp: Option<(&str, bool)>,
    user: Option<(&str, bool)>,
) {
    e.u8(0x01);
    if make {
        e.bytes(&[0x42; 32]);
    } else {
        e.str("x");
    }
    e.u8(0x02);
    if make {
        e.map(1 + u64::from(rp.is_some())).str("id").str("x");
        metadata(e, rp);
        e.u8(0x03)
            .map(1 + u64::from(user.is_some()))
            .str("id")
            .bytes(b"u");
        metadata(e, user);
        e.u8(0x04)
            .array(1)
            .map(2)
            .str("alg")
            .i32(-7)
            .str("type")
            .str("public-key");
    } else {
        e.bytes(&[0x42; 32]);
    }
}

fn metadata(
    e: &mut canokey_ctap::response::encoding::Encoder<&mut [u8]>,
    field: Option<(&str, bool)>,
) {
    if let Some((key, text)) = field {
        e.str(key);
        if text {
            e.str("metadata");
        } else {
            e.bool(false);
        }
    }
}
