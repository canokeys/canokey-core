// SPDX-License-Identifier: Apache-2.0
fn main() {
    println!("cargo:rerun-if-env-changed=CANOKEY_ADMIN_VERSION");
    println!("cargo:rerun-if-env-changed=CANOKEY_CORE_SHA");
}
