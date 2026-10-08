// SPDX-License-Identifier: Apache-2.0
fn main() {
    for variable in ["CANOKEY_HOST_LINK_LIBRARIES", "CANOKEY_HOST_LINK_OPTIONS"] {
        println!("cargo:rerun-if-env-changed={variable}");
        if let Ok(arguments) = std::env::var(variable) {
            for argument in arguments.split('|').filter(|argument| !argument.is_empty()) {
                if variable == "CANOKEY_HOST_LINK_LIBRARIES" {
                    println!("cargo:rerun-if-changed={argument}");
                }
                println!("cargo:rustc-link-arg-bin=fido-hid-over-udp={argument}");
            }
        }
    }
    for variable in ["CANOKEY_PCSC_LINK_LIBRARIES", "CANOKEY_PCSC_LINK_OPTIONS"] {
        println!("cargo:rerun-if-env-changed={variable}");
        if let Ok(arguments) = std::env::var(variable) {
            for argument in arguments.split('|').filter(|argument| !argument.is_empty()) {
                if variable == "CANOKEY_PCSC_LINK_LIBRARIES" {
                    println!("cargo:rerun-if-changed={argument}");
                }
                println!("cargo:rustc-link-arg={argument}");
            }
        }
    }
}
