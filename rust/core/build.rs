// SPDX-License-Identifier: Apache-2.0
// CMake supplies the same version field used by the C firmware. Standalone
// Cargo builds use the core's development-only 0.0.0 convention.
fn main() {
    for name in ["OATH", "PIV"] {
        println!("cargo:rerun-if-env-changed=CANOKEY_{name}_VERSION");
        let value =
            std::env::var(format!("CANOKEY_{name}_VERSION")).unwrap_or_else(|_| "0.0.0".into());
        let parts: Vec<u8> = value
            .split('.')
            .map(|part| {
                assert!(
                    !part.is_empty()
                        && part.bytes().all(|b| b.is_ascii_digit())
                        && (part.len() == 1 || !part.starts_with('0')),
                    "invalid release version"
                );
                part.parse()
                    .expect("release version component must fit a byte")
            })
            .collect();
        assert_eq!(parts.len(), 3, "release version must have three components");
        let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        std::fs::write(
            output.join(format!("{}_version.rs", name.to_lowercase())),
            format!("const {name}_VERSION: [u8; 3] = {:?};\n", parts),
        )
        .unwrap();
    }
}
