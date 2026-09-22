<!-- SPDX-License-Identifier: Apache-2.0 -->
# OATH implementation and normal validation

The explicit ADMIN + PASS + OATH composition runs through the independent Rust
core and USB CCID. No legacy C applet, dispatcher or session manager is linked.
`oath/` is a safe, allocation-free `no_std` domain crate without APDU/status-word
or FFI dependencies. `core/oath_protocol.rs` owns wire adaptation using common
APDU and byte-TLV primitives; `core/oath_backend.rs` binds typed repositories
and MAC to raw platform capabilities. CTAP/PIV/OpenPGP/NFC remain absent.

## Command coverage

OATH AID is `A0000005272101`. Commands use CLA 00 (10 for ISO command chaining).
Except SELECT, VALIDATE and the YubiKey compatibility routes, an installed
access code requires successful OATH authentication; ADMIN PIN is separate.

| Command | Parameters/body | Implemented behavior |
| --- | --- | --- |
| SELECT A4 | P1=04, P2=00, AID | Version 6.0.0, stable handle; challenge/algorithm when locked |
| PUT 01 | P1/P2=0, name/key, optional properties/counter | Create credential, reject duplicate names; SHA-1/256/512, HOTP/TOTP |
| DELETE 02 | P1/P2=0, name | Clear PASS references before tombstoning the record |
| RENAME 05 | P1/P2=0, old/new names | Preserve logical ID and enumeration position |
| SET CODE 03 | P1/P2=0, key/challenge/proof, or empty key | Existing 16-byte access-key proof/set/clear; no new KDF |
| VALIDATE A3 | P1/P2=0, proof/host challenge | Session grant and mutual HMAC-SHA1 proof |
| LIST A1 | P1/P2=0 | Name/type metadata in physical storage order |
| CALCULATE A2 | P1=0, P2=0/1, name/challenge | Full/truncated digest; durable HOTP preincrement; touch policy |
| CALCULATE ALL A4 | P1=0, P2=0/1, challenge | Bounded pages, HOTP and touch markers; full/truncated TOTP |
| SEND REMAINING A5 | Existing continuation | A5/61FF page cursor; no repeated completed calculation |
| SET DEFAULT 55 | P1=1/2, P2=enter 0/1, name | Bind a HOTP stable ID to PASS |
| YubiKey 01 | P1=10/30/38, P2=0 | Serial / PASS HMAC slot 1/2, before OATH authentication gate |
| ADMIN RESET OATH 05 | ADMIN selected and verified | Clear PASS OATH bindings, records and access code; regenerate handle |

Name/key lengths are 1–64 bytes, digits 4–8, TOTP challenge length 1–8.
Properties use raw tag 78 plus flags, not a BER length. HOTP initial counter
zero calculates counter one first, committing the increment before HMAC.
Increasing single-CALCULATE requires eight-byte, nondecreasing challenges and
accepts equality. The original C CALCULATE ALL inconsistency is preserved
explicitly: a decreasing or non-eight-byte challenge still calculates, without
lowering the stored challenge. Migration does not silently fix that behavior.

The adapter owns at most 288 command bytes and a 256-byte response page.
GET RESPONSE consumes prepared bytes; A5 advances the applet cursor. No full
credential table is allocated. The current composition reports version 6.0.0,
matching this migration baseline; future version reporting should share the
management identity service rather than grow per-applet version constants.

## Storage and presence

- `/rust/oath-meta`: 26 bytes, version/key-present/handle8/access-key16.
- `/rust/oath-records`: 146-byte entries: stable big-endian ID4 plus versioned
  142-byte credential codec (name/key lengths, kind/algorithm, digits,
  properties, name64, key64, moving factor8).
- A tombstone keeps its ID and zeros its credential. New IDs exceed every
  existing live/tombstone ID; reused file slots cannot alias PASS bindings.
  Full OATH reset clears PASS bindings before resetting the ID namespace.
- `/rust/pass1`: two version-2 72-byte slots. OATH slots store ID and display
  name, never the key. Earlier Rust version-1 36-byte slots upgrade atomically.
- Raw C storage copies prefix/replacement/suffix to a temporary file and then
  renames it. File caches are word aligned. Appending retains the C 64 KiB
  free-space reserve. Mount failure never formats, and old C records are not
  imported or overwritten. Uncertain writes disable storage until remount.

Rust owns the 30-second request-bound press/release wait. C only polls raw
input/ticks and services CCID time extensions without reentering Rust. A
consumed OATH touch cannot also trigger PASS output. This is synchronous
main-loop operation, not the future full multi-transport scheduler.

## Reproduce normal validation

From the parent CIU repository:

```sh
cargo +nightly-2026-09-04 test --manifest-path canokey-core/rust/oath/Cargo.toml
cmake -S canokey-core/rust -B build/rust-core-oath -G Ninja -DCANOKEY_APPLET_OATH=ON
cmake --build build/rust-core-oath
ctest --test-dir build/rust-core-oath --output-on-failure
.venv-hil/bin/python tools/hil/rust_oath_smoke.py --host build/rust-core-oath/oath-host
cmake --preset devkit-rust-oath
cmake --build --preset build-devkit-rust-oath
# Flash only the HEX produced after the mandatory vector/ResumeLoader gate.
.venv-hil/bin/python tools/hil/rust_oath_smoke.py --touch --output /tmp/oath-usb.json
.venv-hil/bin/python tools/hil/devkit_ctl.py --list
.venv-hil/bin/python tools/hil/rust_oath_persistence.py --control <current-control-port> --output /tmp/oath-persistence.json
```

These device scripts use a dedicated DevKit, reset OATH and write throwaway
credentials/PASS slots. Successful completion leaves OATH empty, access code
unset and PASS slots off; ADMIN PIN remains 123456. No boundary, injected-fault,
fuzz or differential campaign is included.

On 2026-09-22, five domain tests, 68 host APDU checks, 64 USB checks (65 with
actual user touch), and 29 reset/power-cycle checks passed. Real HMAC results
are checked independently with host OpenSSL/Python HMAC. Coverage includes all
three algorithms, full/truncated output, ordinary command chaining, LIST/ALL
pagination, rename/delete/reuse, access-code mutual authentication, PASS binding,
YubiKey HMAC before authentication and common GET RESPONSE. Reset and genuine
CIU power loss preserve handle/access key, HOTP counter and PASS binding while
clearing the session grant. Local reports: `hil-reports/rust-oath-20260922/`.

Host fixtures exercise actual HOTP keyboard bytes. Physical OATH touch passed;
physical keyboard typing into a capture target has not been tested. New OATH
firmware remains installed. NFCC and legacy C credential migration are deferred.
