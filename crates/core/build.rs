#[path = "codegen/ctap.rs"]
mod ctap;
#[path = "codegen/release.rs"]
mod release;

fn main() {
    release::main();
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
        let version = release::version_bytes(&value);
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
