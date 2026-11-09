// SPDX-License-Identifier: Apache-2.0
extern crate std;

// Command options are tested with both boolean values and absent/empty auth.
// CTAP makeCredential forbids up; getAssertion forbids rk, even when false.
pub fn cases() -> std::vec::Vec<(bool, std::vec::Vec<u8>, Option<u8>)> {
    use canokey_ctap::status::Status;
    use canokey_ctap::response::encoding::Encoder;
    let mut cases = std::vec::Vec::new();
    for make in [false, true] {
        for key in ["rk", "up", "uv", "other"] {
            for value in [false, true] {
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
                    e.u8(if make { 0x07 } else { 0x05 })
                        .map(1)
                        .str(key)
                        .bool(value);
                    if empty_auth {
                        e.u8(if make { 0x08 } else { 0x06 }).bytes(&[]);
                    }
                    e.finish().unwrap();
                    let length = 256 - e.writer().len();
                    let error = match (make, key) {
                        (true, "up") => Some(Status::InvalidOption as u8),
                        (false, "rk") => Some(Status::UnsupportedOption as u8),
                        _ => None,
                    };
                    cases.push((make, wire[..length].to_vec(), error));
                }
            }
        }
    }
    cases
}
