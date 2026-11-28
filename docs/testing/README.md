# Testing and host compositions

Run commands from the repository root. Rust unit/integration tests remain under
the owning crate. `tests/integration/` holds Python end-to-end regressions;
`tests/support/` supplies C harnesses and standalone Rust hardware fixtures;
`tests/native/` covers native helpers. Shared external vectors are in
`tests/fixtures/`; Rust-only wire vectors remain beside their Rust tests.
`tests/card` builds the APDU card executables used by the Python applet oracles.
They construct the real Core with Rust record/clock fakes and native C crypto;
they do not call a core C ABI. The LittleFS capacity fixture uses the same
independent Python checks.
The LittleFS storage runner is also Rust; C models flash faults and calls the
runner through explicit test-only function pointers. `runtime-composition`
checks invalid pointer/length pairs and overlapping certificate responses.
`hid-core` and `usb-sessions` are Rust binaries using direct storage, device
and staging fakes. The USB session fixture retains C imports only for the DCD
and clock/timer boundary. It covers cross-transport ownership, immutable IN
packets, reset cleanup, IRQ arrival boundaries and CCID presence polling during
HID execution. Its Provider also selects the presence-progress path; no
platform storage/device/staging C callbacks are linked into these binaries.
The Rust `apdu-replay` binary uses the same composition and retains the existing
line protocol, response draining, slot-power and fault-injection controls.
The PC/SC driver is a Rust cdylib exposing the IFD handler v3 ABI. `pcsc-abi`
links it against the installed C headers and verifies platform typedef/layout,
error results and cancellation of the killable polling callback. The Python
PC/SC and OATH suites exercise the actual driver with independent oracles.

`tests/integration/ctap_fixture.py` generates a self-signed test attestation
certificate valid for one day, with the packed-attestation subject, CA=false
constraint and AAGUID extension. CTAP regressions verify the full packed
attestation, including certificate fields, AAGUID and signature. This identity
is for tests and does not establish production attestation trust.

## Prerequisites

Initialize submodules recursively. Install CMake, a C compiler, CMocka, OpenSSL
and PC/SC development headers. Select a Python environment containing
`tests/integration/requirements.txt` using `-DPython3_EXECUTABLE=/absolute/path`.
On Homebrew, pass `-DPCSC_INCLUDE_DIR=/opt/homebrew/opt/pcsc-lite/include/PCSC`
if CMake cannot discover the headers. The root Rust toolchain is pinned.

```sh
cargo test -p canokey-protocol
python3 tests/check_rust_profiles.py
python3 tests/test_rust_transports.py
cmake -S . -B build/host -DENABLE_TESTS=ON -DENABLE_APDU_REPLAY=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel 2
ctest --test-dir build/host --output-on-failure
```

The Rust feature test matrix runs the empty, single-applet and full Core
profiles. FFI covers empty, CTAP-only and full. The portable CTAP crate
exposes mechanism features and tests empty, streaming-only and full.

```sh
full=admin,pass,oath,openpgp,piv,ctap,ndef
for features in "" admin pass oath openpgp piv ctap ndef "$full"; do
    cargo test -p canokey-rust-core --no-default-features --features "$features"
done
for features in "" ctap "$full"; do
    cargo test -p canokey-rust-ffi --no-default-features --features "$features"
done
for features in "" streaming streaming,schema; do
    cargo test -p canokey-ctap --no-default-features --features "$features"
done
```

Core CTest never discovers platform fixtures in a parent checkout. CIU owns
those tests through its standalone `tests/host` CMake entrypoint. Core owns the
generic device runner and transport tests, executed by its `rust-transports`
CTest across USB combinations, CCID, HID, NFC and device lifecycle profiles.
Each runs with and without `native-platform`. CIU selects its own production
Provider in `platform/rust-core` and disables the native fixture projection.
Rust CI checks formatting, workspace Clippy style and complexity, and supported
applet and transport profiles. FFI and host also enforce unsafe-block comments
and public unsafe API contracts. Protocol, transport-runtime and FFI run a
focused truncation check. The workflow documents individual lint exceptions.

`cargo test -p canokey-ports` checks the committed C projection of record IDs,
board-information selectors and chip-ID size against the Rust contracts. After
an intentional contract change, regenerate the header from the core root:

```sh
rustc --edition=2024 crates/ports/codegen/abi.rs -o /tmp/canokey-port-abi
/tmp/canokey-port-abi --output crates/ports/include/port_abi.h
```

## Transport and CTAP regressions

The wire tests in `tests/CMakeLists.txt` replay packet sequences and expected
responses from `tests/fixtures/` through the Rust test card. The runner
reports results by case ID and checks CCID, NFC, WebUSB control, bulk CCID
and HID output where applicable.

- USB cases cover split CCID headers, control requests, deferred lifecycle
  cleanup, retained WebUSB state, and cross-channel and cross-interface
  ownership.
- SELECT and chain cases cover AIDs, disabled applets, CLA/P1/P2 validation,
  short and extended APDU admission, retained authorization, and recovery.
- NFC cases cover inline and staged request boundaries, rejected envelopes,
  WTX timing and tick wrap. They check response cancellation for unexpected
  frames after WTX and the deferred deselect echo.
- Authentication and storage-fault tests verify signatures, response windows,
  failed and short file reads, stale-source rejection, and recovery across
  CCID, WebUSB, HID and NFC. The session-yield suite checks ownership of
  retained PIV and OpenPGP operations.
- The largeBlobs vectors check deterministic upload, clipped reads, response
  chunks and retransmission. Regenerate them with
  `python3 tests/support/large_blob_vectors.py`.
- Rust CTAP tests verify GetInfo encoding and stream literal parser and
  unknown-CBOR inputs across every fragment boundary.

These host tests model packet and timer events. Physical USB, RF and the
complete product call-path stack are qualified on hardware.

The full host CI and its deb-producing job use Ubuntu 24.04 together. The pinned
pinentry 1.2.1 mock requires libassuan API 2; binary deb, GnuPG and FIDO caches
include the distribution to prevent reuse across incompatible runner ABIs.

The historical C-to-Rust case mapping identifies the original regressions
and their initial replacements. Use the current suites above for validation.
[Legacy test replacement ledger](https://github.com/canokeys/canokey-core/blob/e93d926a0b4c14342e29a22b92c54a35370dea72/docs/testing/legacy-test-coverage.md)

## Fuzzing

`CANOKEY_FUZZING` builds `apdu-fuzzer`, a Rust/libfuzzer-sys harness that drives the
Rust core through the same volatile-record backend as `apdu-replay`. Inputs
are framed records (`[tag:u8][len:u16-LE][payload]`): APDU execution with
automatic GET RESPONSE chaining (`0x00`), slot power (`0x01`), one-shot storage
faults (`0x02`), full runtime reset (`0x03`) and raw APDU exchange (`0x04`,
without draining). It invokes Rust Core APIs directly.
Slot power and full reset clear sessions, selection and pending responses.
Durable card state persists across inputs inside
the fuzzer process. Use a dedicated build directory with Clang; every C
object in it is coverage-instrumented and linked against ASan/UBSan:

```sh
cmake -S . -B build/fuzz -DCANOKEY_PROFILE=full -DCANOKEY_FUZZING=ON \
  -DCANOKEY_VIRTUAL_CARD=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$(brew --prefix llvm)/bin/clang"
cmake --build build/fuzz --target apdu-fuzzer -j 8
build/fuzz/apdu-fuzzer tests/fixtures/fuzz-seeds -max_total_time=600 -timeout=30
# Replay one artifact or a directory of units once:
build/fuzz/apdu-fuzzer <file-or-dir> -runs=0
```

The named built-in seeds in `tests/fixtures/fuzz-seeds/` are generated by
`tests/support/fuzz_seeds.py`; hash-named imported/mutated coverage inputs are
retained separately and carry no valid-path claim. `--import-legacy <dir>` wraps
raw corpora as APDU records. `--refresh-builtins` replaces only named generated
seeds. Validate the baseline statuses and response shapes before accepting them:

```sh
python tests/support/fuzz_seeds.py --validate-only --replay build/replay/apdu-replay
python tests/support/fuzz_seeds.py tests/fixtures/fuzz-seeds \
  --refresh-builtins --replay build/replay/apdu-replay
```

The replay build registers `fuzz-seed-baselines` alongside `apdu-replay`.
The `fuzz-smoke` ctest runs 60 seconds on a temporary copy of the committed seeds
so it cannot rewrite the source corpus. It only proves the harness stays
functional; long campaigns are manual. Panics, asserts, arithmetic overflow
and sanitizer reports are the bug oracle. For differential comparison of a
device against the host engine, see `tools/hil/differential_replay.py` in the
platform repository.

`ENABLE_TESTS` enables the LittleFS helper suite and native ASan/UBSan coverage.
`BUILD_TESTING` controls regression registration. Native crypto cleanup also
requires Linux ASan/LeakSanitizer coverage; macOS alone is not a leak oracle.
Platform storage integration fixtures require explicit
`CANOKEY_PLATFORM_STORAGE_FIXTURE` and `CANOKEY_PLATFORM_STORAGE_STUBS` paths
from the CIU port. Host-only checkouts do not depend on parent hardware sources.

## Explicit profiles

`CANOKEY_PROFILE` defaults to `full`. Use separate build directories per profile.

| Profile | Applets |
| --- | --- |
| full | ADMIN, PASS, OATH, OpenPGP, PIV, CTAP, NDEF |
| none | No applets |
| admin-pass | ADMIN, PASS |
| oath | ADMIN, PASS, OATH |
| openpgp | ADMIN, PASS, OATH, OpenPGP |
| piv | PIV |
| ctap | ADMIN, CTAP |
| custom | Exactly the `CANOKEY_APPLET_*` flags selected by the caller |

Named profiles express intentional test combinations. In `custom`, OpenPGP does
not silently enable OATH or PASS. Tests that exercise multiple applets are
registered only when all their dependencies are selected; standalone applet
fixtures retain their own protocol and crypto checks. Cargo features likewise describe capabilities;
board profiles may intentionally combine applets. Virtual card and replay tools
require the complete applet set. Virtual card defaults on only for `full`.

```sh
cmake -S . -B build/piv -DCANOKEY_PROFILE=piv
cmake -S . -B build/openpgp-only -DCANOKEY_PROFILE=custom -DCANOKEY_APPLET_OPENPGP=ON
```

## External clients and hardware

The FIDO installer patches the pinned PC/SC client to retain other clients'
selection on disconnect and reselect FIDO after reconnect. Its fake-connection
regressions run before any device tests; firmware still requires explicit FIDO
selection after logical slot power/reset.

The external FIDO2 and U2F suites set `CANOKEY_TEST_NFC_AUTO_TAP=1` on
their virtual PC/SC daemon. This supplies a fresh NFC presence event for each
FIDO APDU while preserving the session. The `virtual-pcsc` test
exercises single-use NFC presence with this option disabled.

Go manifests belong to `tests/pcsc/`. Compile/run each legacy Go test file
separately because helper names overlap:

```sh
go -C tests/pcsc test -v admin_test.go
```

These tests operate on a connected reader and may write or reset credentials.
`tests/hardware/` contains physical GPG/PIV/FIDO checks; use a dedicated device.
The shell runner `tests/pcsc/run-nontouch-tests.sh` resolves its Go module itself.
The CI workflow and Docker recipes use the same paths. No hardware tests run as
an implicit part of Cargo unit tests.

The usb-sessions executable also sweeps USB reset/reconfiguration inside actual
Core erasure through its Memory capability. The same Provider and staging backend
remain installed for the process lifetime; the one-shot IRQ hook never enters
Core. Three retained states cover PIN authorization, unread FIDO response and
PKE-backed HID RX. Its USB_CLEANUP_IRQ markers report each state's wipe count
and the total number of passing injections. All reached erasure call sites are
tested under both lifecycle forms; the current full profile has200 injections.
The interrupted service cannot reopen class RX or execute injected class traffic.
A subsequent service restores admission exactly once, with stale output denied,
authorization revoked and PKE released. The injection points cover the reached erasure calls. Physical timing and
instruction-level IRQ or endpoint failures require separate acceptance.

`ctap-normal` verifies254-byte RP disclosure decisions, first-byte/suffix
mutations, packed attestations and the signed full RP hash through Rust's real
host APDU applet. These tests do not establish physical or release acceptance.

`nfc-source-faults` is a separate CTest process of the NFC-enabled transport
runner (`--nfc-source-faults`). It uses one fixed Provider, production NFC
FIFO/IRQ and dispatch, actual Core and native key operations. The staging and
Memory capabilities inject failed reads and HALT/deselect before/after reads,
at each reached64-byte consumer erasure, and during clear/release. Per-case
NFC_SOURCE_CASE markers record fault, source reads, single cleanup/release,
zero key operations and recovery. Deselect also checks the deferred protocol
echo, independently of suppressed APDU output. A healthy reference request
establishes reached injection points and two native key operations.
These schedules cover the modeled read and erasure boundaries.


### Native response-file reads

The optional platform LittleFS fixture also registers
`native-storage-response`. It runs the response-file checks through the
real native storage adapter and platform transaction engine over Core APDUs.
The platform fixture must inject file-read results below its production service
validation; injecting at ck_platform_read_at would miss a service that rejects
all short reads. The driver independently verifies complete registration and
recovery signatures and probes GET RESPONSE before command replacement.

The file system and service are real and the fixture models physical flash.
Replay builds with host sanitizers enabled instrument the native fixture and
LittleFS C sources with ASan/UBSan. Platform CI runs this fixture with Linux
leak checks.

```sh
ctest --test-dir <platform-fixture-build> \
  -R '^native-storage-response$' --output-on-failure
```
