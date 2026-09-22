<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent Rust core rewrite

The standalone `rust/CMakeLists.txt` builds zero applets by default. The optional
ADMIN + PASS profile composes a Rust ADMIN APDU adapter and a Rust PASS service.
No C dispatcher, C session manager or legacy C applet is linked. The optional OATH profile adds Rust OATH; other applets remain absent. See [module boundaries](docs/module-boundaries.md) and the
[current ADMIN/PASS profile](docs/admin-pass.md).

## Ownership

- `protocol/`: common safe APDU parsing, streaming frame/TLV primitives, command
  chaining and response planning; no applet dependencies.
- `core/engine.rs`: transport/session ownership, grants, selection and response
  continuation. `registry.rs` explicitly composes enabled protocol adapters and
  services; the engine does not know PASS record or command sizes.
- `core/admin.rs`, `pass_protocol.rs`: ADMIN command validation, status mapping,
  PIN operations and PASS management wire format.
- `core/auth.rs`: typed durable PIN mechanism, without APDU/status words.
- `core/pass.rs`, `pass/`: slot service, versioned codec, static output and HMAC.
  No APDU/status words, authentication policy or OATH placeholder.
- `core/output.rs`: physical gesture interpretation and bounded keyboard job.
- `core/services.rs`: typed storage and cryptographic capabilities.
- `core/interface.rs`: the app/platform unsafe Rust boundary (host-only panic/abort glue also uses unsafe); main-loop only,
  serialized and non-reentrant. Input and output APDU buffers may alias.
- `interfaces/rust-core/`: USB descriptors and CCID transport. C owns framing,
  reports and endpoint transfers, never business dispatch.

## Normal host validation

From the parent CIU repository:

```sh
cmake -S canokey-core/rust -B build/rust-core-empty -G Ninja
cmake --build build/rust-core-empty
ctest --test-dir build/rust-core-empty --output-on-failure
cmake -S canokey-core/rust -B build/rust-core-pass -G Ninja -DCANOKEY_APPLET_PASS=ON
cmake --build build/rust-core-pass
ctest --test-dir build/rust-core-pass --output-on-failure
```

`CANOKEY_APPLET_PASS` currently selects the ADMIN + PASS composition: one
selectable AID (ADMIN), plus PASS as a service and physical-output entrypoint.
The fixture exercises the actual C ABI with OpenSSL primitives and in-place
APDU buffers. It covers default PIN initialization/query/verify/change,
ordinary response chaining, static output, gesture/backpressure,
RFC 2202 HMAC, persistence and session reset. These are normal functional tests.

## USB firmware

The parent CIU presets `devkit-rust-core` and `devkit-rust-admin-pass` build
separate zero-applet and ADMIN/PASS firmware. Both reuse C USB core/endpoint
mechanics with separate control buffers; no legacy `src/` or `applets/` files
are linked. The ADMIN/PASS profile adds CCID plus keyboard HID, typed backend
callbacks and an independent `/rust` namespace on the existing LittleFS volume.
It never formats a failed mount or reads/replaces old C credential records.

CCID accepts short APDUs and common ISO chaining. ADMIN currently accepts only
CLA 00; command-chaining admission belongs to the selected protocol adapter. USB callbacks only
queue events; Rust calls occur in the main loop. CCID power/reset clears grants,
command state and pending output. The OATH profile connects the existing
YubiKey serial/HMAC wire commands to platform identity and the PASS service.

The mandatory CIU boot gate compares vector address zero, all 48 slots,
reserved entries and handler mappings, early ResumeLoader invocation and the
recovery object code with the normal firmware. Addresses may relocate. NFCC is
deferred. Do not call this stage a complete migration of C ADMIN: remaining
commands and hardware validation limits are listed in the profile document.

## OATH integration

`oath/` owns typed credentials, HOTP/TOTP and access-code authentication with
no APDU dependency. `core/oath_protocol.rs` owns OATH wire fields/status mapping;
`core/oath_backend.rs` supplies bounded record storage and primitive adapters.
The `devkit-rust-oath` preset builds ADMIN + PASS + OATH explicitly. See
[OATH implementation and normal validation](docs/oath.md) for commands, storage,
host/USB tests, physical touch and reset/power-cycle results.
