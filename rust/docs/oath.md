<!-- SPDX-License-Identifier: Apache-2.0 -->
# OATH implementation and normal validation

The explicit ADMIN + PASS + OATH composition runs through the independent Rust
core and USB CCID. No legacy C applet, dispatcher or session manager is linked.
`core/src/applets/oath/` groups the APDU-free domain/authentication modules,
record codec, protocol adapter and repository. The adapter uses common APDU and
byte-TLV primitives; repository and MAC borrow disjoint storage/crypto ports.
The safe core is allocation-free `no_std`; FFI lives in a separate crate.
CTAP/PIV/OpenPGP/NFC remain absent.

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
VALIDATE consumes the SELECT challenge after a successful proof and rotates it,
so a response cannot be replayed within the same selection.
Increasing credentials require eight-byte, nondecreasing challenges and accept
equality in both CALCULATE and CALCULATE ALL. Rejected challenges return 6982;
the former C CALCULATE ALL bypass is intentionally removed. Enumeration is not
a multi-record transaction: earlier accepted updates can already be durable
when a later record rejects the request. An error aborts the continuation.

The adapter owns at most 288 command bytes and a 256-byte response page.
GET RESPONSE consumes prepared bytes; A5 advances the applet cursor. No full
credential table is allocated. CMake passes CANOKEY_OATH_VERSION from the same
release configuration used by C; core/build.rs validates it and generates the
three SELECT bytes. Standalone builds without a release configuration use
development version 0.0.0, matching the common version policy.

## Storage and presence

- `02`: version/key-present/handle8, followed by access-key16 only when set
  (10 or 26 bytes).
- `03`: next-ID watermark4, then live entries. Each entry stores ID4,
  six header bytes, actual name/key bytes and moving-factor8, all explicitly
  encoded. Deletion atomically removes the entry; there are no tombstones.
- The watermark survives deletion, so a stale PASS binding cannot alias a new
  credential. Full OATH reset clears PASS bindings before resetting IDs.
- `00`: two compact PASS slots. OATH slots store ID and display name, never
  the key. No previous-format upgrade path is included.
- Updates stage the header, live prefix, replacement and suffix, then rename.
  File caches are word aligned. Insertions retain C's 64 KiB free-space reserve
  for other applets. Mount failure never formats. Provision fresh storage;
  previous C/Rust data layouts are not imported. Uncertain writes disable
  storage until remount.

Rust owns the 30-second request-bound press/release wait. C only polls raw
input/ticks and services CCID time extensions without reentering Rust. A
consumed OATH touch cannot also trigger PASS output. This is synchronous
main-loop operation, not the future full multi-transport scheduler.

## Reproduce normal validation

From the parent CIU repository:

```sh
cargo +nightly-2026-09-04 test --manifest-path canokey-core/rust/Cargo.toml -p canokey-protocol -p canokey-rust-core --features admin,pass,oath
cmake -S canokey-core/rust -B build/rust-core-oath -DCANOKEY_APPLET_OATH=ON -DCANOKEY_VERSIONS_FILE="$PWD/versions.cmake"
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
firmware remains installed. NFCC is deferred; credential migration is not supported.


## OATH protocol review (2026-09-23)

The current A1/A2/A5 protocol and access-code commands are authoritative; the
historical CanoKey web page's 03/04/06 instruction numbers are not a target.
C source is reference material, not authority for undocumented permissiveness.

- SELECT starts a new OATH challenge/validation exchange. With an access code,
  even same-AID reselection requires VALIDATE again. This is intentionally
  distinct from ADMIN's same-AID PIN grant preservation. The host must not
  treat fetching a fresh challenge as authorization to calculate.
- VALIDATE without an installed access code is typed AccessCodeMissing and
  maps to 6984. An incorrect proof remains 6A80; unrelated Invalid errors are
  not globally remapped.
- RENAME resolves the old name before testing the new name. When both are
  invalid, old-name absence wins (6984). No C error-priority compatibility is
  promised where the protocol does not specify it.
- A5 requires P1=P2=0 and an empty body. LIST/CALCULATE ALL page generation is
  bounded by Le. After a complete page ending in 61FF, GET RESPONSE returns
  6986, while A5 advances the applet cursor. GET RESPONSE remains available
  for ISO-fragmented prepared replies such as SELECT. These are separate
  continuation mechanisms, not interchangeable aliases.
- Executing a new non-A5 OATH command cancels the old applet page cursor; an
  execution error also abandons it. Parsing an incomplete transport command
  is not itself a successful applet operation.
- CALCULATE parses the challenge before asking for touch. presence_attempted
  marks input consumed by a wait, including failed waits, so the same gesture
  cannot later cause PASS typing. It does not mean presence was authorized.
  NFC presence semantics will be defined with the future NFC profile.

CTest now registers oath-normal: a Python standard-library driver owns actual
APDU assertions and runs oath-host as its card backend. Registering oath-host
alone would only start a stdin interpreter and could falsely pass on empty
input. The suite resides in core/tests/oath_normal.py and requires no CIU
checkout or USB modules in host mode; the CIU script is a thin USB entrypoint.
The documented root versions.cmake path is supplied explicitly by the caller,
not discovered by reaching outside the standalone core repository.

HIL cleanup is success-only. On failure the dedicated test device may retain
throwaway credentials or bindings; a rerun begins by resetting OATH/PASS and
requires the default ADMIN PIN. Factory reset's five physical touches and
keyboard typing remain outside this normal OATH APDU suite.


The 2026-09-23 follow-up passed 80 host APDU checks, 76
USB checks, 29 reset/power-cycle checks and 19
ADMIN USB checks. Both release-version and development-version OATH CTest
profiles run two tests and pass. Local evidence is in
`hil-reports/rust-oath-review-20260923/`; no new physical-touch run was performed.
