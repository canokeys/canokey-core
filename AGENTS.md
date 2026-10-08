# AGENTS.md — canokey-core

## Current repository

CanoKey Core is a Rust workspace. See [README](README.md),
[architecture](docs/architecture/README.md) and [testing](docs/testing/README.md).
Product code lives in `crates/{core,protocol,ports,ffi,host}`. Native ABI headers
are in `native/include`, crypto facades in `native/crypto`, and filesystem
helpers in `native/storage`. Dependencies in `third_party/` are Git submodules;
retain their gitlinks and pinned revisions when relocating them.

`reference/legacy-c` is an immutable historical snapshot with checksum provenance.
Never edit, compile or include it. `docs/history` contains superseded migration
plans and the old C guide; historical APIs there are not implementation guidance.

## Boundaries

- `core` is `no_std` and forbids unsafe code. Keep applet policy, authorization,
  wire adapters, record codecs and repositories here; shared mechanisms must
  not depend on applets. Cross-applet orchestration belongs in `flows`.
- `protocol` owns structural encoding and portable transport state machines,
  with no applet or native dependencies.
- `ports/contracts` contains safe capability contracts; `binding.rs` selects
  outer static production or injectable test bindings; generic `Platform`
  families carry capability types through core routing. `native-crypto` owns
  reusable C crypto imports; device/storage C calls belong to the outer platform or
  `ffi/platform` compatibility projection. Presence policy stays portable.
  Do not re-export native adapters through core. Keep safe default erasure
  available through the binding API for workspace cleanup.
- `ffi/abi`, `ffi/runtime`, `ffi/transport` and `ffi/platform` own C entrypoints,
  lifecycle integration, hardware-facing transport facades and assembly.
  Validate raw pointer/length pairs and preserve alias-safe in-place APDUs.
- Only serialized main-loop execution may enter the core. Interrupts queue
  events; no callback may reenter an active mutable runtime borrow.
- Root Cargo owns Rust builds. Root CMake owns host/native composition; do not
  restore a second build entrypoint inside `crates`. Profiles express explicit
  applet sets; custom applet selection must not install unrelated applets.

## Compatibility and resources

- Preserve AIDs, commands, algorithms, wire encodings, defaults, retry ordering,
  record formats and authentication policy during structural changes. Document
  intentional protocol changes near the corresponding applet and add coverage.
- Session ownership is shared across HID, CCID, WebUSB and NFC. Use one shared
  transient workspace, never independent per-applet worst-case buffers.
- No dynamic allocation in firmware. CIU single-call-path stack budget is
  6000 bytes, including callers and interrupt frames; other platforms must
  document their own budget. Preserve source
  optimization and LTO settings when moving build inputs.
- Stream large APDU bodies, key imports, certificates, public-key encodings and
  responses. Do not increase short APDU buffers to avoid streaming. The bounded
  standalone extended FIDO-over-CCID path does not authorize general extended APDUs.
- PKE memory is transient staging, not durable request state. Fully parse staged
  bytes before crypto, progress callbacks, keepalive, presence waits or session
  yield can clobber them. Preserve only necessary bounded semantic fields.
- Never use Flash as generic RX scratch. Persistent writes need a protocol-owned
  purpose and explicit authorization, bounds, cleanup and wear considerations.
- Close response/input leases on completion, replacement, failure and reset.
  `GET RESPONSE` must not expose a stale chain. Cross-transport preemption must
  preserve ownership/security rules and invalidate stale generations.
- Do not format storage on mount failure or silently reinterpret old record layouts.
  Compact Rust record IDs map to two-character hexadecimal names; provision fresh
  storage for incompatible layout changes. Host virtual storage is a versioned
  record image, not a LittleFS image.
- Keep CCID slot-status polling live during FIDO presence/progress. It must not
  execute arbitrary APDUs or discard queued power/reset requests during release.

## Crypto contracts

- Preserve weak-symbol override APIs, CRT validation, peer-point checks and
  secret wiping. Native primitive implementations remain in canokey-crypto or
  the platform; retain platform overrides when the generic PSA wrapper is inactive.
- RSA imports and private operations reject inconsistent CRT components; never
  repair imported DP/DQ/QP. Use-time verification remains required.
- Weierstrass ECDH validates field bounds and curve membership before multiplying.
  X25519 rejects all-zero results. SM2 agreement validates both peer points and
  rejects infinity, with initiator-Z-first KDF ordering; plain SM2 ECDH stays rejected.
- Preserve hedged production ML-DSA signing; deterministic behavior is restricted
  to explicitly selected KAT modes. No heap allocations or unconditional logging.

## Validation and conventions

Use English for source comments, docs and diagnostics. Use explicit Rust endian
conversions at wire boundaries. C glue uses existing endian helpers and
`DBG_MSG`/`ERR_MSG`, not new bare printf calls in production library code.
Keep feature guards and zero-applet builds valid. Public declarations must match
C/Rust ABI sizes and signatures.

Run the affected Rust suites and CTest integrations described in
[testing](docs/testing/README.md). Check both DevKit and NFCC for shared core,
crypto or build changes; preserve the 48-vector/ResumeLoader boot gate. Record
pre-existing overflow separately; never flash oversized diagnostic images.
Linux ASan/LeakSanitizer results are required before claiming native cleanup is
leak-free. Physical tests mutate credentials and need a dedicated resettable device.
