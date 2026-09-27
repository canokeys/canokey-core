// SPDX-License-Identifier: Apache-2.0
//! GetInfo's fixed schema lives in Flash; only card state is encoded at runtime.
use super::{MAX_REQUEST, credential, credential_request, large_blob, pin, provision};
use crate::ports::Record;
use canokey_protocol::cbor::{EncodeError, Encoder};
include!(concat!(env!("OUT_DIR"), "/ctap_info.rs"));
pub(super) fn encode(
    output: &mut [u8],
    flags: u8,
    configured: bool,
    minimum: u8,
    used: u8,
    sm2_algorithm: i32,
) -> Result<usize, EncodeError> {
    let capacity = output.len();
    let always_uv = flags & pin::ALWAYS_UV != 0;
    let mut e = Encoder::new(output);
    e.encoded(HEADER).array(if always_uv { 3 } else { 4 });
    if !always_uv {
        e.encoded(U2F);
    }
    e.encoded(VERSIONS_EXTENSIONS)
        .bytes(&provision::AAGUID)
        .encoded(OPTIONS)
        .bool(always_uv)
        .encoded(CLIENT_PIN)
        .bool(configured)
        .encoded(OPTIONS_END)
        .u16(MAX_REQUEST as u16)
        .encoded(PIN_PROTOCOLS)
        .u8(credential_request::MAX_LIST as u8)
        .u8(8)
        .u8(credential::ID_BYTES as u8)
        .encoded(ALGORITHMS);
    if !cfg!(feature = "ctap-restrict-algorithms") {
        e.i32(sm2_algorithm);
    }
    e.encoded(ALGORITHMS_END)
        .u16(large_blob::LIMIT)
        .u8(12)
        .bool(flags & pin::FORCE_CHANGE != 0)
        .u8(13)
        .u8(minimum)
        .encoded(LIMITS)
        .u8(Record::CTAP_CREDENTIALS - used)
        .encoded(RESET)
        .bool(flags & pin::LONG_RESET != 0)
        .encoded(END);
    e.finish()?;
    Ok(capacity - e.writer().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    // The previous field-by-field implementation is an independent schema
    // oracle for the generated fragments, including variable-width integers.
    fn reference(
        output: &mut [u8],
        flags: u8,
        configured: bool,
        minimum: u8,
        used: u8,
        sm2_algorithm: i32,
    ) -> Result<usize, EncodeError> {
        let capacity = output.len();
        let mut e = canokey_protocol::cbor::Encoder::new(output);
        let result = (|| {
            let versions = if flags & pin::ALWAYS_UV != 0 {
                ["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"].as_slice()
            } else {
                ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"].as_slice()
            };
            e.map(22).u8(1).array(versions.len() as u64);
            for version in versions {
                e.str(version);
            }
            e.u8(2)
                .array(7)
                .str("credBlob")
                .str("credProtect")
                .str("minPinLength")
                .str("largeBlobKey")
                .str("hmac-secret")
                .str("hmac-secret-mc")
                .str("thirdPartyPayment");
            e.u8(3).bytes(&provision::AAGUID);
            e.u8(4).map(10).str("rk").bool(true).str("up").bool(true);
            e.str("alwaysUv").bool(flags & pin::ALWAYS_UV != 0);
            e.str("credMgmt").bool(true);
            e.str("authnrCfg").bool(true);
            e.str("clientPin").bool(configured);
            e.str("largeBlobs").bool(true);
            e.str("pinUvAuthToken").bool(true);
            e.str("setMinPINLength").bool(true);
            e.str("makeCredUvNotRqd").bool(true);
            e.u8(5).u16(MAX_REQUEST as u16);
            e.u8(6).array(2).u8(1).u8(2);
            e.u8(7).u8(credential_request::MAX_LIST as u8);
            e.u8(8).u8(credential::ID_BYTES as u8);
            e.u8(9).array(1).str("usb");
            let algorithms = [-7, -8, sm2_algorithm, -49];
            let algorithms = &algorithms[..if cfg!(feature = "ctap-restrict-algorithms") {
                2
            } else {
                4
            }];
            e.u8(10).array(algorithms.len() as u64);
            for &algorithm in algorithms {
                e.map(2)
                    .str("alg")
                    .i32(algorithm)
                    .str("type")
                    .str("public-key");
            }
            e.u8(11).u16(large_blob::LIMIT);
            e.u8(12).bool(flags & pin::FORCE_CHANGE != 0);
            e.u8(13).u8(minimum);
            e.u8(14).u32(0);
            e.u8(15).u8(32);
            e.u8(16).u8(4);
            e.u8(20).u8(Record::CTAP_CREDENTIALS - used);
            e.u8(22).array(1).str("packed");
            e.u8(24).bool(flags & pin::LONG_RESET != 0);
            e.u8(26).array(2).str("nfc").str("usb");
            e.u8(29).u8(63);
            e.u8(31).array(3).u8(2).u8(3).u8(4);
            e.finish()
        })();
        result?;
        e.finish()?;
        Ok(capacity - e.writer().len())
    }
    #[test]
    fn generated_schema_matches_all_dynamic_fields() {
        for flags in 0..8 {
            for configured in [false, true] {
                for minimum in [4, 23, 24, 63] {
                    for used in [0, 76, 77, 100] {
                        for algorithm in [
                            i32::MIN,
                            -65537,
                            -65536,
                            -257,
                            -256,
                            -54,
                            -25,
                            -24,
                            0,
                            23,
                            24,
                            255,
                            256,
                            65535,
                            65536,
                            i32::MAX,
                        ] {
                            let mut expected = [0; 527];
                            let mut actual = [0; 527];
                            let n = reference(
                                &mut expected,
                                flags,
                                configured,
                                minimum,
                                used,
                                algorithm,
                            )
                            .unwrap();
                            assert_eq!(
                                encode(&mut actual, flags, configured, minimum, used, algorithm),
                                Ok(n)
                            );
                            assert_eq!(actual, expected);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn generated_schema_rejects_every_short_buffer() {
        let mut expected = [0; 527];
        let n = reference(&mut expected, 0, false, 63, 0, i32::MIN).unwrap();
        for size in 0..n {
            let mut guarded = [0xa5; 529];
            assert_eq!(
                encode(&mut guarded[1..1 + size], 0, false, 63, 0, i32::MIN),
                Err(EncodeError)
            );
            assert_eq!(guarded[0], 0xa5);
            assert!(guarded[1 + size..].iter().all(|b| *b == 0xa5));
        }
    }
}
