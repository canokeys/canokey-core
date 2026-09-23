<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent Rust core rewrite

One Cargo workspace contains `protocol`, safe `core`, and `ffi`. No C dispatcher,
C session manager or legacy C applet is linked. Device profiles explicitly select
zero applets, ADMIN + PASS, ADMIN + PASS + OATH, those plus OpenPGP, or PIV
alone/combined. See
[module boundaries](docs/module-boundaries.md),
[ADMIN + PASS implementation checkpoint](docs/admin-pass.md), and
[OATH implementation and normal validation](docs/oath.md), and
[OpenPGP implementation and normal validation](docs/openpgp.md).

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
- `core/src/ports/`: disjoint mutable storage/crypto/device capabilities and an
  immutable erasure capability. OATH does not use RefCell or share a mutable
  whole-platform handle. Stored bytes and record IDs are unchanged.
- `ffi/src/entrypoints.rs`: serialized C ABI and alias-safe RX/TX borrows;
  `ffi/src/platform/`: storage, crypto and device adapters, with volatile
  erasure in the device module. Safe core forbids unsafe code at the crate root.
- `interfaces/rust-core/`: retained C USB/CCID/HID framing and endpoint mechanics.

The `admin`, `pass`, `oath`, `openpgp` and `piv` core/FFI features are independent.
Only enabled services own registry state and run installation. PASS has no AID;
ADMIN is selected by `admin`, not by `pass`. OATH-to-PASS binding requires both
services; without PASS its binding/HMAC-slot commands are unavailable. CIU and
host device-equivalent profiles explicitly combine their required features.
Workspace crates deny warnings through inherited Cargo lints. Check both isolated
features and the combined configuration. Cargo's host-only SHA-256 test
dependency is not included in the firmware dependency graph.

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
is retained for the current CCID profile. OpenPGP and [PIV](docs/piv.md) use
production incremental consumers and independent host cryptographic validation;
future multi-transport scheduling remains outside these device profiles.

## Normal validation

From the parent CIU repository:

```sh
cargo +nightly-2026-09-04 test --manifest-path canokey-core/rust/Cargo.toml -p canokey-protocol -p canokey-rust-core --features admin,pass,oath
cmake -S canokey-core/rust -B build/rust-core-oath -DCANOKEY_APPLET_OATH=ON -DCANOKEY_VERSIONS_FILE="$PWD/versions.cmake"
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

The independent [Rust PIV profile](docs/piv.md) supports management authentication,
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

The `ctap` feature currently implements only the stateless CCID FIDO
`authenticatorGetInfo` request. It uses a fixed RAM response and adds no Flash
record. CTAPHID, PIN/UV, credentials and large CBOR streaming remain in the C
implementation until their transport and scratch-buffer contracts are migrated
together.
