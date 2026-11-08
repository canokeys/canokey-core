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
    // Keep generated fixed limits synchronized with their owning modules.
    const {
        assert!(MAX_REQUEST <= u16::MAX as usize);
        assert!(credential_request::MAX_LIST == 16);
        assert!(credential::ID_BYTES == 34);
        assert!(large_blob::LIMIT == 4096);
    }
    let capacity = output.len();
    let mut encoder = Encoder::new(output);
    canokey_ctap::info::encode(
        INFO,
        &canokey_ctap::info::State {
            aaguid: &provision::AAGUID,
            always_uv: flags & pin::ALWAYS_UV != 0,
            client_pin: configured,
            force_change: flags & pin::FORCE_CHANGE != 0,
            minimum_pin_length: minimum,
            remaining_credentials: Record::CTAP_CREDENTIALS - used,
            long_reset: flags & pin::LONG_RESET != 0,
            nfc: cfg!(feature = "ctap-nfc"),
            algorithm: sm2_algorithm,
        },
        &mut encoder,
    )?;
    Ok(capacity - encoder.writer().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/c312-getinfo/vectors.rs"
    ));

    #[test]
    fn schema_matches_executed_pinned_c_vectors() {
        let mut tested = 0;
        for &(flags, configured, minimum, used, algorithm, restricted, nfc, before, after) in
            C312_VECTORS
        {
            if restricted != cfg!(feature = "ctap-restrict-algorithms")
                || nfc != cfg!(feature = "ctap-nfc")
            {
                continue;
            }
            let mut actual = [0; 527];
            let n = encode(&mut actual, flags, configured, minimum, used, algorithm).unwrap();
            let mut expected = [0; 527];
            let mut e = Encoder::new(&mut expected[..]);
            e.encoded(before)
                .u32(crate::release::FIDO_FIRMWARE)
                .encoded(after)
                .finish()
                .unwrap();
            let expected_len = 527 - e.writer().len();
            assert_eq!(&actual[..n], &expected[..expected_len]);
            tested += 1;
        }
        assert_eq!(
            tested,
            if cfg!(feature = "ctap-restrict-algorithms") {
                64
            } else {
                32
            }
        );
    }

    // Field-by-field schema follows C Core a349b268, with explicit product
    // identity and transport capabilities. Keep array order and omissions exact.
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
            e.map(if flags & pin::FORCE_CHANGE != 0 {
                22
            } else {
                21
            })
            .u8(1)
            .array(versions.len() as u64);
            for version in versions {
                e.str(version);
            }
            e.u8(2)
                .array(7)
                .str("credBlob")
                .str("credProtect")
                .str("hmac-secret")
                .str("hmac-secret-mc")
                .str("largeBlobKey")
                .str("minPinLength")
                .str("thirdPartyPayment");
            e.u8(3).bytes(&provision::AAGUID);
            e.u8(4).map(9).str("rk").bool(true);
            e.str("alwaysUv").bool(flags & pin::ALWAYS_UV != 0);
            e.str("credMgmt").bool(true);
            e.str("authnrCfg").bool(true);
            e.str("clientPin").bool(configured);
            e.str("largeBlobs").bool(true);
            e.str("pinUvAuthToken").bool(true);
            e.str("setMinPINLength").bool(true);
            e.str("makeCredUvNotRqd").bool(flags & pin::ALWAYS_UV == 0);
            e.u8(5).u16(MAX_REQUEST as u16);
            e.u8(6).array(2).u8(1).u8(2);
            e.u8(7).u8(credential_request::MAX_LIST as u8);
            e.u8(8).u8(credential::ID_BYTES as u8);
            e.u8(9);
            if cfg!(feature = "ctap-nfc") {
                e.array(2).str("nfc").str("usb");
            } else {
                e.array(1).str("usb");
            }
            let algorithms = [-7, -8, -49, -48, sm2_algorithm];
            let algorithms = &algorithms[..if cfg!(feature = "ctap-restrict-algorithms") {
                2
            } else {
                5
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
            if flags & pin::FORCE_CHANGE != 0 {
                e.u8(12).bool(true);
            }
            e.u8(13).u8(minimum);
            e.u8(14).u32(crate::release::FIDO_FIRMWARE);
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
