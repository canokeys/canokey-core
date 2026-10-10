# Transport runtime and composition

This crate composes the safe core with platform capabilities and runs the device
lifecycle and USB, HID, CCID, keyboard, WebUSB and NFC transports. Rust hosts and
firmware supply their own `composition::Provider`; product C exports belong to
the outer platform.

Default features are empty. The explicit `native-platform` feature selects
native callback imports for the LittleFS fault-injection fixture. It does not
export a C API. Its C import declarations and generated contract constants live
in `crates/ports/include`; native crypto imports belong to `native-crypto`.
The PC/SC plugin's external ABI belongs to the host crate.

See [architecture](../../docs/architecture/README.md) for serialization and buffer
ownership. No applet policy belongs here.
