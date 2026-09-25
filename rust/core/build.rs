#[path = "codegen/ctap.rs"]
mod ctap;

fn main() {
    if std::env::var_os("CARGO_FEATURE_CTAP").is_some() {
        ctap::generate_info();
        ctap::generate_response();
    }
    cfg_aliases::cfg_aliases! {
        has_applet: { any(feature = "admin", feature = "oath", feature = "openpgp", feature = "piv", feature = "ctap") },
        persistent_applet: { any(feature = "oath", feature = "openpgp", feature = "piv", feature = "ctap") },
        classic_presence: { any(feature = "oath", feature = "openpgp", feature = "piv") },
        crypto_applet: { any(feature = "openpgp", feature = "piv", feature = "ctap") },
    }
    for (name, file) in [
        ("CANOKEY_OATH_VERSION", "oath_version.rs"),
        ("CANOKEY_PIV_VERSION", "piv_version.rs"),
    ] {
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
