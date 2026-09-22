// SPDX-License-Identifier: Apache-2.0
// CMake supplies the same version field used by the C firmware. Standalone
// Cargo builds use the core's development-only 0.0.0 convention.
fn main() {
    println!("cargo:rerun-if-env-changed=CANOKEY_OATH_VERSION");
    let value = std::env::var("CANOKEY_OATH_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let parts: Vec<u8> = value
        .split('.')
        .map(|part| {
            assert!(
                !part.is_empty()
                    && part.bytes().all(|b| b.is_ascii_digit())
                    && (part.len() == 1 || !part.starts_with('0')),
                "invalid OATH version"
            );
            part.parse()
                .expect("OATH version component must fit a byte")
        })
        .collect();
    assert_eq!(parts.len(), 3, "OATH version must have three components");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(
        output.join("oath_version.rs"),
        format!("const OATH_VERSION: [u8; 3] = {:?};\n", parts),
    )
    .unwrap();
}
