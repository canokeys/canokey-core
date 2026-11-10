// SPDX-License-Identifier: Apache-2.0
// Product capabilities; the shared host compiler owns GetInfo wire structure.
pub fn generate_info(firmware: u32) {
    use canokey_ctap::schema::{Algorithm, Boolean, Field, get_info};
    let restricted = std::env::var_os("CARGO_FEATURE_CTAP_RESTRICT_ALGORITHMS").is_some();
    let nfc = std::env::var_os("CARGO_FEATURE_CTAP_NFC").is_some();
    let mut algorithms = vec![Algorithm::Fixed(-7), Algorithm::Fixed(-8)];
    if !restricted {
        algorithms.extend(
            canokey_ports::mldsa::PARAMETER_SETS
                .into_iter()
                .map(|parameter| Algorithm::Fixed(parameter.cose)),
        );
        algorithms.push(Algorithm::Configured);
    }
    let source = get_info(&[
        Field::Versions {
            u2f: true,
            vendor: &[],
        },
        Field::Extensions(&[
            "credBlob",
            "credProtect",
            "hmac-secret",
            "hmac-secret-mc",
            "largeBlobKey",
            "minPinLength",
            "thirdPartyPayment",
        ]),
        Field::Aaguid,
        Field::Options(&[
            ("rk", Boolean::Fixed(true)),
            ("alwaysUv", Boolean::AlwaysUv),
            ("credMgmt", Boolean::Fixed(true)),
            ("authnrCfg", Boolean::Fixed(true)),
            ("clientPin", Boolean::ClientPin),
            ("largeBlobs", Boolean::Fixed(true)),
            ("pinUvAuthToken", Boolean::Fixed(true)),
            ("setMinPINLength", Boolean::Fixed(true)),
            ("makeCredUvNotRqd", Boolean::MakeCredUvNotRqd),
        ]),
        Field::MaxMessageSize(crate::config::CtapRequestConfig::MAX_MESSAGE_SIZE),
        Field::PinUvAuthProtocols,
        Field::MaxCredentialCountInList(16),
        Field::MaxCredentialIdLength(34),
        Field::Transports(if nfc { &["nfc", "usb"] } else { &["usb"] }),
        Field::Algorithms(&algorithms),
        Field::MaxSerializedLargeBlobArray(4096),
        Field::ForcePinChange,
        Field::MinimumPinLength,
        Field::FirmwareVersion(firmware),
        Field::MaxCredBlobLength(32),
        Field::MaxRpIdsForSetMinPinLength(4),
        Field::RemainingDiscoverableCredentials,
        Field::AttestationFormats(&["packed"]),
        Field::LongTouchForReset,
        Field::TransportsForReset(&["nfc", "usb"]),
        Field::MaxPinLength(63),
        Field::AuthenticatorConfigCommands(&[0x02, 0x03, 0x04]),
    ]);
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(path.join("ctap_info.rs"), source).unwrap();
}
