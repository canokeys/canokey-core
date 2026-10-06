// SPDX-License-Identifier: Apache-2.0
//! Shared release-field generator for Cargo and standalone native fixtures.
pub fn version_bytes(value: &str) -> [u8; 3] {
    let bytes: Vec<u8> = value
        .split('.')
        .map(|part| {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "version component must be decimal"
            );
            part.parse().expect("version component must fit one byte")
        })
        .collect();
    bytes
        .try_into()
        .expect("version must have exactly three components")
}

pub fn main() {
    let mut release = String::new();
    for (name, declaration, default, max) in [
        (
            "CANOKEY_FIDO_FIRMWARE_VERSION",
            "FIDO_FIRMWARE: u32",
            "0",
            u32::MAX,
        ),
        (
            "CANOKEY_USB_BCD_DEVICE",
            "USB_BCD_DEVICE: u16",
            "0x0100",
            u16::MAX as u32,
        ),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_else(|_| default.into());
        let number = if let Some(hex) = value.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).expect("hexadecimal release field")
        } else {
            value.parse::<u32>().expect("decimal release field")
        };
        assert!(number <= max, "{name} exceeds its ABI width");
        release.push_str(&format!("pub const {declaration} = {number};\n"));
    }
    println!("cargo:rerun-if-env-changed=CANOKEY_CTAPHID_DEVICE_VERSION");
    let value = std::env::var("CANOKEY_CTAPHID_DEVICE_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let version = version_bytes(&value);
    release.push_str(&format!(
        "pub const CTAPHID_DEVICE: [u8; 3] = {version:?};\n"
    ));
    let out = std::env::var_os("OUT_DIR").expect("OUT_DIR set");
    std::fs::write(
        std::path::Path::new(&out).join("release_versions.rs"),
        release,
    )
    .expect("write release fields");
}
