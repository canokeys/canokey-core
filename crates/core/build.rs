#[path = "codegen/ctap.rs"]
mod ctap;

fn main() {
    let mut release = String::new();
    for (name, declaration, default) in [
        ("CANOKEY_FIDO_FIRMWARE_VERSION", "FIDO_FIRMWARE: u32", "0"),
        ("CANOKEY_USB_BCD_DEVICE", "USB_BCD_DEVICE: u16", "0x0100"),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_else(|_| default.into());
        let number = if let Some(hex) = value.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).expect("hexadecimal release field")
        } else {
            value.parse::<u32>().expect("decimal release field")
        };
        release.push_str(&format!("pub const {declaration} = {number};\n"));
    }
    println!("cargo:rerun-if-env-changed=CANOKEY_CTAPHID_DEVICE_VERSION");
    let value = std::env::var("CANOKEY_CTAPHID_DEVICE_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let version: Vec<u8> = value
        .split('.')
        .map(|part| part.parse().expect("version byte"))
        .collect();
    assert_eq!(version.len(), 3);
    release.push_str(&format!(
        "pub const CTAPHID_DEVICE: [u8; 3] = {version:?};\n"
    ));
    let out = std::env::var_os("OUT_DIR").expect("OUT_DIR set");
    std::fs::write(
        std::path::Path::new(&out).join("release_versions.rs"),
        release,
    )
    .expect("write release fields");
    if std::env::var_os("CARGO_FEATURE_CTAP").is_some() {
        ctap::generate_info();
        ctap::generate_response();
    }
    cfg_aliases::cfg_aliases! {
        // APDU applets need shared runtime support; PASS only supplies credential output.
        has_applet: { any(feature = "ndef", feature = "admin", feature = "oath", feature = "openpgp", feature = "piv", feature = "ctap") },
        // These applets retain presence requests; ADMIN uses a separate factory-reset gesture.
        persistent_applet: { any(feature = "oath", feature = "openpgp", feature = "piv", feature = "ctap") },
        // Classic applets consume boolean presence; CTAP needs polling and typed failures.
        classic_presence: { any(feature = "oath", feature = "openpgp", feature = "piv") },
        // Key-operation applets need crypto workspace; OATH/PASS keep bounded MAC buffers.
        crypto_applet: { any(feature = "openpgp", feature = "piv", feature = "ctap") },
    }
    for (name, file) in [
        ("CANOKEY_OATH_VERSION", "oath_version.rs"),
        ("CANOKEY_PIV_VERSION", "piv_version.rs"),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_else(|_| "0.0.0".to_owned());
        let bytes: Vec<u8> = value
            .split('.')
            .take(3)
            .map(|part| part.parse::<u8>().unwrap_or(0))
            .collect();
        let mut version = [0u8; 3];
        version[..bytes.len()].copy_from_slice(&bytes);
        let out = std::env::var_os("OUT_DIR").expect("OUT_DIR set");
        let path = std::path::Path::new(&out).join(file);
        let text = format!(
            "pub const {}: [u8; 3] = {:?};\n",
            file.trim_end_matches(".rs").to_ascii_uppercase(),
            version
        );
        std::fs::write(path, text).expect("write generated version");
    }
}
