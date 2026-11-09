// SPDX-License-Identifier: Apache-2.0
extern crate std;

// Every option value must be boolean, including unrecognized names. Type
// admission precedes command-only up/rk admission, with absent or empty auth.
// Values below are false, true, null, 0, -1, empty bytes/text, array and map.
pub fn cases() -> std::vec::Vec<(bool, std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::response::encoding::Encoder;
    use canokey_ctap::status::Status;
    let mut cases = std::vec::Vec::new();
    for make in [false, true] {
        for key in [
            "rk",
            "up",
            "uv",
            "other",
            "unknown-option-longer-than-32-bytes",
        ] {
            for value in [
                &b"\xf4"[..],
                &b"\xf5"[..],
                &b"\xf6"[..],
                &b"\x00"[..],
                &b"\x20"[..],
                &b"\x40"[..],
                &b"\x60"[..],
                &b"\x80"[..],
                &b"\xa0"[..],
            ] {
                for empty_auth in [false, true] {
                    let mut wire = [0x00; 256];
                    let mut e = Encoder::new(&mut wire[..]);
                    e.map(if make { 5 } else { 3 } + u64::from(empty_auth));
                    e.u8(0x01);
                    if make {
                        e.bytes(&[0x42; 32]);
                    } else {
                        e.str("x");
                    }
                    e.u8(0x02);
                    if make {
                        e.map(1).str("id").str("x");
                        e.u8(0x03).map(1).str("id").bytes(b"u");
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
                    e.u8(if make { 0x07 } else { 0x05 }).map(1).str(key);
                    e.encoded(value);
                    if empty_auth {
                        e.u8(if make { 0x08 } else { 0x06 }).bytes(&[]);
                    }
                    e.finish().unwrap();
                    let length = 256 - e.writer().len();
                    let error = match (make, key, value) {
                        (_, _, value) if value != b"\xf4" && value != b"\xf5" => {
                            Some(Status::CborUnexpectedType as u8)
                        }
                        (true, "up", _) => Some(Status::InvalidOption as u8),
                        (false, "rk", _) => Some(Status::UnsupportedOption as u8),
                        _ => None,
                    };
                    cases.push((make, wire[..length].to_vec(), error));
                }
            }
        }
    }
    cases
}
