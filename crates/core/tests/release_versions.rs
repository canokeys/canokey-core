// SPDX-License-Identifier: Apache-2.0
#[allow(dead_code)]
#[path = "../codegen/release.rs"]
mod release;

#[test]
fn release_versions_require_three_decimal_bytes() {
    assert_eq!(release::version_bytes("1.2.255"), [1, 2, 255]);
    for value in ["", "1.2", "1.2.3.4", "1.2.300", "1..3", "+1.2.3", "a.2.3"] {
        assert!(
            std::panic::catch_unwind(|| release::version_bytes(value)).is_err(),
            "{value}"
        );
    }
}
