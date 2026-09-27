> Historical migration record. Current architecture: [architecture](../architecture/README.md); current commands: [testing](../testing/README.md).

<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust core workspace

The root `../Cargo.toml` owns the five crates in this directory: `protocol`,
`ports`, safe `core`, `ffi` and `host`. Rust owns all applets and the shared
APDU, USB/HID/keyboard/CCID/WebUSB, NFC/NDEF and device-service runtime.
LittleFS, native crypto, thin adapters and platform hardware remain native.
The CMake entry here supports explicit profiles; the repository root builds
the complete Rust host composition. Legacy C sources in `../reference/` are
read-only migration reference and are not part of either build.

See [module boundaries](module-boundaries.md),
[transport migration](transport-migration.md) and
[correctness coverage](../testing/legacy-test-coverage.md). Full firmware resource
and physical acceptance are tracked by the platform repository.

## Organization and ownership

- `protocol/src/apdu/`: envelope/header decoding and chain metadata; `response.rs`
  owns continuation arithmetic and a source-independent cursor. `tlv/length.rs`
  and `tlv.rs` provide incremental structural parsing, without C layout coupling.
- `core/src/runtime/`: a single selection owner in the static registry, transport
  ownership, frame/command lifecycle, response delivery and presence handling.
  `Runtime<R>` uses the same code for device routing and host streaming fixtures.
- `core/src/applets/admin/`: ADMIN wire handling, PIN mechanism and PASS config
  wire schema. `pass/` contains slot domain/codec/service and keyboard output.
- `core/src/applets/oath/`: credential/authentication domain, record codec,
  repository and protocol adapter together. Domain modules have no APDU/SW/FFI
  dependency. Request collection and execution state have disjoint borrows.
- `core/src/applets/openpgp/`: APDU/TLV adapters, domain session/key/PIN services,
  incremental key import and key/certificate repository. Services and repositories
  return domain errors; protocol adapters map them to status words. Registry owns the
  shared key/input/output workspace; no complete certificate/import buffer.
- `core/src/flows/`: typed persistent reset and HOTP keyboard orchestration,
  called only by registry. Flows do not depend on protocol adapters or status
  words. Registry revokes sessions and routes output requests; PASS output only
  owns gesture and byte-draining state.
- `ports/src/`: shared storage/crypto/device/erasure contracts and native
  implementations under `native/`. `core/src/ports/` reexports the safe API.
  Disjoint borrows preserve ownership without a mutable whole-platform handle.
  Record IDs, persistent encodings and the native ABI are unchanged.
- `ffi/src/entrypoints.rs`: serialized C ABI and alias-safe RX/TX borrows;
  `ffi/src/platform/` assembles the backend. CIU and CMake host adapter builds
  select `static-backend`, eliminating capability vtable calls in production.
  Host unit tests use injectable ports (`dynamic-backend` takes precedence when
  all Cargo features are enabled). Both use the same native implementation.
  See [ports/README.md](../../crates/ports/README.md). Core still forbids unsafe code.
- [native/crypto/](../../native/crypto/): thin crypto adapters;
  [native/include/](../../native/include/): native service ABI headers.

The `admin`, `pass`, `oath`, `openpgp` and `piv` core/FFI features are independent.
Only enabled services own registry state and run installation. PASS has no AID;
ADMIN is selected by `admin`, not by `pass`. OATH-to-PASS binding requires both
services; without PASS its binding/HMAC-slot commands are unavailable. CIU and
host device-equivalent profiles explicitly combine their required features.
Workspace crates deny warnings through inherited Cargo lints. Check both isolated
features and the combined configuration. Cargo's host-only SHA-256 test
dependency is not included in the firmware dependency graph.

The C primitive adapters require `RUST_CORE_OPENPGP`, `RUST_CORE_PIV` and/or
`RUST_CORE_CTAP` to match the selected Rust applets. Both the CIU and host CMake
builds supply these flags. ML-KEM streaming is PIV-only; RSA/X25519 require
OpenPGP or PIV, and SM2 requires CTAP or PIV. Disabled operations return an error.
`crypto-profile` tests these boundaries and compares supported public-key output
with the native crypto implementation. The FFI enables fixed HMAC-SHA1 only for
PASS, general MAC for OATH/CTAP, and independent random-number support for
OpenPGP/PIV. This prevents unused `dyn Crypto` methods from retaining primitives
through the vtable. Combined profiles retain the union of applet capabilities.

## Streaming contract

The production short-frame entrypoint feeds the common `FrameDecoder`; packet
input uses `begin_frame/feed_frame/end_frame`. Each intermediate chained APDU
is acknowledged without finalizing the logical command. A pull-backed frame
can feed the same consumer through a 64-byte window. Unread source bytes must
survive consumer callbacks; PKE-backed input requires a command-specific proof
before incremental crypto can reuse the hardware.

Small ADMIN/OATH requests remain bounded collectors. OpenPGP key templates,
messages and objects use incremental consumers, not a larger APDU buffer.
The runtime's response cursor supplies fresh source borrows per chunk, supports
monotonic generators and closes sources on completion, replacement or reset.
OATH A5 pagination remains distinct from ISO GET RESPONSE. Synchronous presence
is retained for the current CCID profile. OpenPGP and [PIV](../applets/piv.md) use
production incremental consumers and independent host cryptographic validation;
future multi-transport scheduling remains outside these device profiles.

## Normal validation

From the parent CIU repository:

```sh
cargo +nightly-2026-09-04 test --manifest-path canokey-core/Cargo.toml -p canokey-protocol -p canokey-rust-core --features admin,pass,oath
cmake -S canokey-core/crates -B build/rust-core-oath -DCANOKEY_APPLET_OATH=ON -DCANOKEY_VERSIONS_FILE="$PWD/versions.cmake"
cmake --build build/rust-core-oath
ctest --test-dir build/rust-core-oath --output-on-failure
```

CTest registers `core-normal`, `oath-normal` and `rust-normal` in the OATH
profile. The normal streaming fixtures drive the actual runtime with a 1,300-byte
key-component template, 8 KiB incremental SHA-256, a 16 KiB object write/read,
and a 4 KiB sequential generated response. They verify bytes, intermediate-frame
acknowledgements, single finalization/commit and source closure. The fixture's
fixed runtime state is below 2 KiB even for the 16 KiB object; host backend
storage is excluded and is not a proposed firmware buffer.

Configure without applet flags for zero applets, or with
`-DCANOKEY_APPLET_PASS=ON` for ADMIN + PASS. The C ABI fixtures exercise in-place
APDU input/output and existing PIN, PASS, HMAC and OATH behavior. Only normal
functional tests are part of this checkpoint.

Use `-DCANOKEY_APPLET_OPENPGP=ON` to add the OpenPGP host suite; its Python
interpreter must have `cryptography`. OpenPGP/PIV host builds link the production
C primitive adapters to canokey-crypto; its generated PSA driver wrappers also
require `jinja2` and `jsonschema` in the CMake-selected Python interpreter. Use
`-DPython3_EXECUTABLE=...` to select an environment with those dependencies.

CIU presets are `devkit-rust-core`, `devkit-rust-admin-pass`,
`devkit-rust-oath`, `devkit-rust-openpgp` and `devkit-rust-piv`. Each retains the mandatory 48-vector/ResumeLoader gate.
NFCC is deferred. Root-level hexadecimal record filenames, the no-autoformat rule and
serialized main-loop C interface remain unchanged.

The independent [Rust PIV profile](../applets/piv.md) supports management authentication,
classical/SM2/PQ operations, source-backed attestation and streamed object storage.
Use `-DCANOKEY_APPLET_PIV=ON` alone or with OpenPGP for its host APDU suite
(`cryptography >= 50` required).

## Compact persistence

Record IDs map directly to two hexadecimal filename characters (`00`..`4c`);
`t` and `s` are atomic-update and streaming temporaries. There is no directory
prefix or filename table. Records store actual PIN, string and key-component
lengths; fixed RAM buffers are not written as padded disk images. OATH removes
deleted entries while retaining a four-byte next-ID watermark. Previous C and
Rust data layouts are unsupported: provision fresh storage, without adding
migration codecs or automatic formatting on mount failure. See each applet's
record layout documentation for exact encodings.

## CTAP migration boundary

The `ctap` feature implements Rust CTAPHID INIT/PING, native/CCID GetInfo and
clientPIN protocols 1/2 with compact durable PIN retries and expiring session tokens,
plus selection and power-on-gated reset with cooperative keepalive/cancellation.
USB endpoint handling stays in C; framing and transaction state live in Rust.
HID requests above 192 bytes and standalone extended FIDO APDUs exceeding the
short CCID buffer borrow PKE under the shared transport session, without Flash
caching. Both accept up to 1024 CTAP bytes and close input before execution. See [the CTAP slice contract](../applets/ctap.md) for supported commands,
stream lifetimes, the shared command boundary, incremental CBOR/minicbor
integration, build/tests and the remaining migration steps. This development
profile does not yet implement credential operations or token authorization consumers.
