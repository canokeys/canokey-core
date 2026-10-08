// SPDX-License-Identifier: Apache-2.0
fn main() {
    if let Err(error) = canokey_rust_host::install_signal_handlers() {
        eprintln!("installing signal handlers: {error}");
        std::process::exit(1);
    }
    let status = canokey_rust_host::run_udp();
    let signal = canokey_rust_host::stopping_signal();
    std::process::exit(if status != 0 {
        status
    } else if signal != 0 {
        128 + signal
    } else {
        0
    });
}
