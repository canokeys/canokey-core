<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent Rust core rewrite

The active target is `rust/CMakeLists.txt`, not the legacy root CMake target.
It builds `core/` with **zero applets by default**. Enabling `CANOKEY_APPLET_PASS`
adds only Rust PASS. It never compiles `src/apdu.c`, `src/device.c`, the C applet
registry, or any source under `applets/`. Existing C product sources come unchanged from `dev`, outside this target.
Previous Rust/C replacement experiments and their C adapters are removed.

## Ownership

- `protocol/`: safe APDU parsing, incremental frame decoding, command-chain
  metadata, response planning/leases and common streaming TLV. No applet dependency.
- `core/engine.rs`: Rust transport ownership, selection, command lifecycle,
  routing and response continuation. There is no C dispatcher or saved tail.
- `pass/`: safe slot rules, record codec and PASS-specific configuration encoding.
- `core/pass.rs`: the first applet; consumes bounded semantic fields and emits
  discovery from stable slot state, using the shared APDU foundation.
- `core/auth.rs`: minimal Rust authentication for PASS management.
- `core/interface.rs` and `interfaces/rust-core/core.h`: C ABI and raw platform
  services only. The C caller delivers frames, sends responses and handles I/O.
  Calls are serialized, non-reentrant and main-loop only; RX/TX may alias.

No default feature enables an applet. PASS is safe Rust with no legacy C ABI:
C ADMIN, C OATH and old PASS exports cannot enter this target.
OATH support is not implemented; existing OATH slot references cannot generate
codes. Future Rust OATH will provide that service explicitly.

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

The C fixture invokes the real Rust ABI with an in-place APDU buffer. PASS tests
cover select, PIN verify, chained configuration, static keyboard output,
GET RESPONSE discovery, RFC 2202 HMAC-SHA1 and reload/reset. OpenSSL supplies
host crypto primitives only. No old applet is used as a fixture or backend.
These are normal functional checks, not fuzz/exhaustive tests.

## Minimal protocol profile

The engine accepts short APDUs and ISO command chaining. Transport frame
aggregation happens before `ck_core_exchange`; incremental frame and TLV
primitives are available in `protocol/` for later transport adapters/applets.
Extended APDUs are not enabled in this first profile. Owner 0 is invalid; a
transport reset/disconnect calls `ck_core_reset` before ownership is transferred.

PASS uses management AID `F0 00 00 00 00`, but does not implement the old ADMIN
applet. SELECT (`00 A4 04 00`) authorizes nothing. VERIFY (`00 20 00 00`, 6-64
PIN bytes) authenticates the session. READ PASS (`00 43 00 00`) streams slot
metadata, WRITE PASS (`00 44 <1|2> 00`) stores a static password/HMAC key/off
configuration, and RESET PASS (`00 13 00 00`) clears both slots. The last three
commands require authentication. All other ADMIN commands are absent.

Platform file 0 contains two packed 71-byte slots. File 1 is a **prototype**
34-byte credential record: SHA-256 PIN digest, retries remaining, maximum
retries (1-15). It must be provisioned externally; there is no default PIN or
unauthenticated provisioning command. Missing credentials fail closed. Each
attempt is durably recorded before hashing; success restores retries, failure
returns `63Cx`, exhausted retries return `6983`, storage failures return `6500`.
Backend writes must be atomic and durable. This is not legacy ADMIN credential
migration or a finished product provisioning design. No device backend is yet
attached to these file IDs.

## USB firmware checkpoint

The CIU port now builds this zero-applet core as `devkit-rust-core`. The C
interface files `interfaces/rust-core/usb.c` and `ccid.c` reuse the existing
USB core, endpoint driver and CCID bulk endpoint implementation. CCID assembles
short frames; Rust handles APDU semantics. No source in `src/` or `applets/`
is linked. The USB control descriptors own their storage, so this build defines
`USBD_SEPARATE_CONTROL_BUFFER` to avoid the old shared-APDU-buffer hooks.

All Rust entrypoints run in the main loop. USB callbacks only receive/send
bytes and queue session resets; the USB reset generation prevents stale
responses crossing connections. Power on/off resets authorization in Rust.
The device advertises one CCID interface, short APDU exchange and a 271-byte
maximum CCID message (10-byte header plus 261-byte command).

The zero-applet DevKit image has been exercised over USB/PCSC: slot activation,
ordinary APDUs, multi-packet command assembly, disconnect/reconnect, reset and
power cycle. It does not mount or write the credential filesystem. PASS remains
an explicitly enabled host profile; finish device storage/provisioning and
keyboard integration before enabling it on the board. Add Rust OATH only after
PASS; no other applet is implicitly enabled.

CIU startup and ResumeLoader stay unchanged. The firmware gate checks vector
address 0, all 48 slots/order/reserved entries/handler mappings and the early
ResumeLoader call, including byte-for-byte recovery object comparison. Function
addresses may relocate. NFCC is deferred.
