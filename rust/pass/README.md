<!-- SPDX-License-Identifier: Apache-2.0 -->
# Safe PASS library

This crate has no C ABI or dependency on C ADMIN/OATH. It is an optional
Rust-core dependency; it is absent from the zero-applet USB firmware.

- `domain.rs`: typed slots, keyboard output and HMAC challenge rules.
- `codec.rs`: explicit slot record encoding; no Rust struct is serialized.
- `protocol.rs`: PASS configuration and discovery using shared status words.
  It defines no APDU parser or request type. PASS wire configuration is not TLV.

`core/pass.rs` owns the slot repository; `core/pass_protocol.rs` owns wire
configuration and `core/auth.rs` owns authentication. Discovery is generated
by offset from stable slots. With the OATH composition, the registry resolves
a stable credential ID and invokes the OATH service for HOTP keyboard output;
PASS never sees the credential key or file offset. Version-2 slots are 72 bytes
and retain decoding of the earlier 36-byte version-1 slots.

CIU storage and keyboard transport are integrated. Normal host checks cover
output bytes; USB checks cover configuration, binding and HMAC. End-to-end
physical keyboard typing into a capture target remains untested.
