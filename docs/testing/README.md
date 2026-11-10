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
cargo test -p canokey-transport-runtime -p canokey-ports --features canokey-ports/ctap
cargo test -p canokey-rust-core --features admin,pass,oath,openpgp,piv,ctap,ndef
python3 tests/check_rust_profiles.py
python3 tests/test_rust_transports.py
cmake -S . -B build/host -DENABLE_TESTS=ON -DENABLE_APDU_REPLAY=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel 2
ctest --test-dir build/host --output-on-failure
```

Core CTest never discovers platform fixtures in a parent checkout. CIU owns
those tests through its standalone `tests/host` CMake entrypoint. Core owns the
generic device runner and transport tests, executed by its `rust-transports`
CTest across USB combinations, CCID, HID, NFC and device lifecycle profiles.
Each runs with and without `native-platform`. CIU selects its own production
Provider in `platform/rust-core` and disables the native fixture projection.
Rust CI checks
formatting, Clippy correctness/suspicious lints and supported applet/transport
profiles. Style-only Clippy lints are not yet enforced; explicit adapter drops
are allowed to end borrows before workspace erasure. Host/std and supported
firmware feature profiles are checked in separate Cargo invocations.

Shared transport tests use only fake request/response and chip backends; they
cover CTAPHID framing, channels, timeouts and final IN completion, ISO-DEP
retransmission/WTX, register recovery and NFC provisioning without a product
applet. Ports tests check configuration defaults, exact-read fallback and staged
transaction cleanup. Product tests retain applet policy and adapter integration.

`cargo test -p canokey-ports` checks the committed C projection of record IDs,
board-information selectors and chip-ID size against the Rust contracts. After
an intentional contract change, regenerate the header from the core root:

```sh
rustc --edition=2024 crates/ports/codegen/abi.rs -o /tmp/canokey-port-abi
/tmp/canokey-port-abi --output crates/ports/include/port_abi.h
```

## C 3.1.2 parser oracle

`tests/fixtures/c312-cbor-skip` records native execution of the pinned TinyCBOR
skip function with the release recursion limit. It covers63 values at four
known-parent depths (252 executions). The C sources are read from Git objects
and compiled only in a temporary directory; this is a skip-contract oracle,
not a complete C CTAP or transport run. Regenerate using a TinyCBOR repository
that contains the pinned revision:

```sh
python3 tests/support/c312_cbor_skip.py --tinycbor-repository /path/to/tinycbor
cargo test -p canokey-rust-core --features ctap cbor_skip_tests
```

Rust tests consume the saved literal vectors through each production command
parser, including nested hmac-secret/COSE values and every fragment boundary.
They also cover truncated payloads and clearing an abandoned request. The
CTAPHID suite separately verifies that same-CID CANCEL aborts fragmented RX
with a sequence error before parser entry, then recovers for a complete request.
Idle/late CANCEL remains silent; foreign CANCEL cannot alter the active RX.

## C 3.1.2 transport comparison

The [portable wire vectors](../../tests/fixtures/c312-ccid/README.md) execute
identical literal input/expected bytes on separate pinned-C and Rust transport
facades. CCID and NFC include real applet dispatch; WebUSB also runs actual EP0
SETUP/OUT/IN/status stages. The HID ownership/admission/channel companions also
exercise native framing and pending output; their explicit C defects remain
outside parity totals. The `c312-*-wire` CTests use the archived
expectations against Rust only; they are not fresh C execution. Regenerate dual
reports with the separate pinned checkout before claiming cross-implementation
parity. Transport vectors do not establish physical timing or CIU stack safety.

`c312-auth-response-wire` adds independent response-contract assertions using
real ADMIN/CTAP provisioning and native crypto. It checks source/buffered
chunking across CCID, WebUSB, native MSG and NFC, including256/257-byte
Ed25519 assertions, large credential-management responses, PQ output and
certificate-backed U2F registration. Its Rust-only CTest is not a fresh C run.
For a paired run with a separate clean pinned C checkout:

```sh
python3 tests/support/c312_auth_response.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/c-build \
  --rust-runner /path/to/nfc-wire/usb-sessions-rust \
  --transport ccid --transport webusb --transport msg --transport nfc \
  --output /path/to/response-contract-report.json
```

The report retains raw wire traces and independently verified results for
each implementation. Their opaque handles and random crypto data differ;
contract checks are counted separately from equal-byte portable vectors.
An explicit raw sensor waveform supplies Rust USB presence. NFC uses the
facade's real active-mode flag. No product authorization is bypassed.

`c312-storage-response-wire` schedules negative/short response-file reads through
the same real facades, probes source closure before replacement, then verifies
normal output recovery. It covers CCID, WebUSB, native MSG/CBOR and NFC;
U2F runs on CCID, WebUSB, native MSG and NFC. Use a separate C build directory
for its file-read seam:

```sh
python3 tests/support/c312_storage_faults.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/c-fault-build \
  --rust-runner /path/to/nfc-wire/usb-sessions-rust \
  --output /path/to/storage-response-report.json
```

The C build forwards ordinary reads to unchanged fs.c. Rust injects at its
Storage capability: generic response reads are exact, while ISO U2F reads
preserve bounded partial progress. Recovery registrations use ordinary presence
and independent certificate/signature verification.
See the [fixture scope](../../tests/fixtures/c312-storage-response/README.md).

`c312-storage-response-nfc-extended` adds Case3E, finite Case4E Le257 and
Case4E Le0000 with actual PKE request staging. It checks response aggregation,
terminal file errors, GET RESPONSE closure and recovery. Same-BN retries and
opposite-BN NAK/control-ACK sequences must not consume another source read:

```sh
python3 tests/support/c312_storage_faults.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/c-fault-build \
  --rust-runner /path/to/nfc-wire/usb-sessions-rust \
  --transport nfc --nfc-extended --output /path/to/nfc-extended-report.json
```

The [extended fixture](../../tests/fixtures/c312-storage-response-nfc-extended/README.md)
records the72 C/90 Rust independent checks. Five E60 literal R-block schedules
also run in `c312-nfc`, including ignored unsolicited ACKs and empty chained
input retries. These host executions do not establish physical RF/WTX timing.

E61's31 NFC cases additionally replay raw MAIN/FIFO/AUX IRQ bytes, RF_STATUS
and FIFO input. An `irq` step encodes three IRQ bytes and one `rf_status` byte
before its optional `packet`; no protocol state is changed by the adapter.
C uses its existing register fake and Rust uses the production Io/facade.
All16 NFC_STATE values, coalesced HALT/ACTIVE, error precedence and old
input/output/Admin grants are covered. Rust services activation cleanup,
execution and response publication in three serialized poll turns. Core NFC
register tests independently cover all256 status bytes, status-read errors,
the active-high FF recovery mask and failed-mask drain-only fallback.

E62 adds28 pending-input cases. Set `service: false` on a NFC FIFO/IRQ step
to inject it without main-loop service; `poll: true` explicitly services the
queued frame. The adapters serialize these as DEFER NFC/IRQ and POLL0 and
preserve production protocol state. Both implementations drain later bounded
frames while pre-execution input owns the reply turn. Rust's real NFC source
fixture also injects R(NAK) at all15 PKE writes, then runs the existing41
source-fault/cancellation cases. Deselect cancellation injection first fires
the real WTX timer so the reader owns the next RF turn.

`c312-nfc-execution` adds E63 execution-time checks. The host-only storage-read
hook forwards real record bytes unchanged; it advances the actual clock and
invokes the production scheduled WTX callback. Reader IRQs run outside the
mutable Io borrow after interrupt unmasking. RF traces record each actual
TXEN; WIRE is only the last-send summary. Eleven normal contracts cover150/
151/300ms callbacks, repeated WTX, tick wrap, early ACK/NAK/deselect/WTX/invalid
frames, complete GetInfo continuation and selected-context reuse. Four
after-WTX wrong-echo/ACK/NAK/deselect cases record known differing RF traces
with `unresolved` dispositions; passing their observation assertions does not
approve parity. Run `tests/support/c312_nfc_execution.py` with `--rust-runner`,
`--output` and optionally `--c-repository`/`--c-build` for fresh paired evidence.
WTX cache behavior, arbitrary schedules and physical RF/IRQ-stack acceptance
remain separate open work.

`c312-select-wire` adds E64:285 literal CCID/WebUSB/NFC SELECT cases covering
transport-specific AIDs, bounded/oversized lengths, byte mutations, P2
precedence, malformed envelopes and response/selection/grant recovery. Core
tests cover all256 P2 bytes and1/16/64-byte fragmentation separately. An AID
longer than the16-byte matching window is drained and rejected at complete
SELECT finalization; it cannot bypass USB FIDO deselection. See the
[literal contracts](../../tests/fixtures/c312-select/README.md). Configuration,
CLA/P1 mutation breadth and physical USB/RF acceptance remain open.

`c312-session-yield-wire` checks retained PIV SM2 state and native HID borrowing
through real CCID/WebUSB/HID facades. Inline PING/WINK preserve card scratch;
MSG/CBOR and staged requests refuse a retained agreement. AES challenges,
PIN grants, independent SM2 derivation, PIV objects and OpenPGP certificate
chains/responses cover admission and recovery. See the
[fixture scope](../../tests/fixtures/c312-session-yield/README.md).

## C 3.1.2 synchronization gate

`c312-nfc-inline-wire` adds 540 malformed inline NFC contracts with actual
retained FIDO/NDEF/OpenPGP state. `c312-correctness-wire` reuses 134 historical
USB cases with explicit current decisions for 17 unequal outputs. The original
reports stay unchanged; these decisions preserve Rust correctness rather than
reproducing C defects. See the fixture READMEs and the
[decision record](../sync/c312-correctness-decisions.md). WTX and physical/source
acceptance remain separate.

The [synchronization manifest](../sync/README.md) tracks the fixed C commit
range and independent baseline findings. Run `python3 tests/check_c312_sync.py
--source-repository /path/to/pinned-c-core` for the release check. It currently
fails because source reviews and acceptance are unfinished. The CI draft check
uses `--structure-only`; that validates records without granting release
acceptance. Gate regressions run with `python3 -m unittest discover -s tests
-p test_c312_sync.py -v`. The CIU platform companion must pass separately.

The full host CI and its deb-producing job use Ubuntu 24.04 together. The pinned
pinentry 1.2.1 mock requires libassuan API 2; binary deb, GnuPG and FIDO caches
include the distribution to prevent reuse across incompatible runner ABIs.
Formatting skips only the frozen parser/resident/staging oracle modules; their
source bytes remain fixed. The ordinary shared ClientPIN cases are formatted
with the rest of the workspace.

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

The `c312-usb-control-wire` CTest replays literal HALT/GET_STATUS and descriptor
stages through the actual Rust USB facade. Its adjacent pinned-C report keeps
malformed GET_STATUS and busy-descriptor reply differences explicit. The ffi
transport matrix also verifies driver dispatch for clearing an already-clear
endpoint; physical DATA-toggle effects require board acceptance. See
[control vectors and reproduction](../../tests/fixtures/c312-usb-control/README.md).

The c312-usb-lifecycle-wire CTest replays33 Rust literal cases for duplicate
configuration retention, actual reset/reconfiguration and empty native C0
routing. Independent pinned-C comparison and limitations are documented in
[the fixture](../../tests/fixtures/c312-usb-lifecycle/README.md). Generic APDU
GET RESPONSE remains6986; native C0 without retained output is6D00.

The c312-usb-readiness-wire CTest adds deferred-service class callback schedules
and pending-native error precedence. Its pinned-C adapter enters the real class
DataOut callback. Four error cases preserve the unresolved L8 output difference;
they are not parity. The ffi matrix separately rejects stale cleanup completion
after a reset and verifies receive rearming. See
[readiness vectors](../../tests/fixtures/c312-usb-readiness/README.md).

The c312-webusb-readiness-wire CTest replays eight E54 cases covering command
refusal before lifecycle cleanup, available status/GET_CONFIGURATION, empty
response-fetch rejection and post-cleanup Admin SELECT recovery. The ffi
interface/backend matrix repeats the gate with and without HID/keyboard.
Fresh-product status does not establish retained pre-reset WebUSB state parity.
See [WebUSB readiness vectors](../../tests/fixtures/c312-webusb-readiness/README.md).

The c312-webusb-retained-wire CTest replays14 E55 cases with existing WebUSB
transactions across deferred lifecycle cleanup: retained status, refused
response/command SETUP, old-source rejection, PIN revocation and recovery.
The ffi matrix separately checks ready/Hold with both lifecycle forms. Its
configuration fixture services cleanup before acknowledging readiness.
See [retained-state vectors](../../tests/fixtures/c312-webusb-retained/README.md)
for exact preconditions and the limits of virtual EP0 schedules.

The usb-sessions executable also sweeps USB reset/reconfiguration inside actual
Core erasure through its Memory capability. The same Provider and staging backend
remain installed for the process lifetime; the one-shot IRQ hook never enters
Core. Three retained states cover PIN authorization, unread FIDO response and
PKE-backed HID RX. Its USB_CLEANUP_IRQ markers report each state's wipe count
and the total number of passing injections. All reached erasure call sites are
tested under both lifecycle forms; the current full profile has200 injections.
The interrupted service cannot reopen class RX or execute injected class traffic.
A subsequent service restores admission exactly once, with stale output denied,
authorization revoked and PKE released. These Rust architectural tests are
separate from the portable C/Rust event counts, physical timing and arbitrary
instruction-level IRQ/endpoint-failure acceptance.

The [C CTAP parser fixture](../../tests/fixtures/c312-parser/README.md) executes
six unchanged pinned parsers with real dependencies. Its generated Rust status
vectors run at every fragment boundary in `cbor_skip_tests`; they supplement
the extracted TinyCBOR depth probe. Reader failure/cancellation injections and
the unchanged C full-RP response regression have separately stated scopes.
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
These41 schedules do not add C/Rust wire-parity cases or physical acceptance;
unknown command/error ordering and arbitrary execution IRQs remain separate.


The c312-large-blob-usb-wire and c312-large-blob-nfc-wire CTests replay
independently generated largeBlobs expectations against Rust. Their paired
C/Rust reports additionally execute unchanged pinned C transport handlers.
See the fixture READMEs for exact commands, execution-time HID IN completion
schedule and explicit storage-fault/physical/resource limitations.


### Native response-file reads

The optional platform LittleFS fixture also registers
`c312-native-storage-response`. It runs the E58 response contracts through the
real native storage adapter and platform transaction engine over Core APDUs.
The platform fixture must inject file-read results below its production service
validation; injecting at ck_platform_read_at would miss a service that rejects
all short reads. The driver independently verifies complete registration and
recovery signatures and probes GET RESPONSE before command replacement.

This adds30 Rust native checks, separately from the paired transport totals.
The file system and service are real; physical flash and timing are modeled.
It does not establish actual USB/NFC hardware behavior or physical corruption
acceptance. In replay builds with host sanitizers enabled, the native fixture
and LittleFS C sources are instrumented with ASan/UBSan and the card host links
the matching runtimes. Platform CI enables this fixture and Linux leak checks.

```sh
ctest --test-dir <platform-fixture-build> \
  -R '^c312-native-storage-response$' --output-on-failure
```

## Disabled-target SELECT oracle

`c312-select-config-wire` adds E65:340 CCID/WebUSB/NFC cases with authenticated
Admin configuration changes and exact readback. It covers disabled NDEF,
OpenPGP, FIDO and all three PIV AID forms, short Case3/4 and WebUSB/NFC extended
Case3/4, P2 precedence, prior selection/grants and config/response recovery.
Disabled NDEF preserves unrelated Admin grants and NFC FIDO; other disabled
targets clear selection. See the
[literal contracts](../../tests/fixtures/c312-select-config/README.md).
The original E64 matrix and full source/physical acceptance remain separate.

## SELECT header and envelope oracle

`c312-select-header-wire` adds E66:618 CCID/WebUSB/NFC cases covering six CLA
values and three P1 values, plus WebUSB/NFC Case2E and valid/malformed Case4E.
Six actual prior contexts verify retained Admin/PIV/OpenPGP PIN grants, NDEF CC
selection, proprietary FIDO intermediate/final rejection and response recovery.
The generator derives expected bytes from pinned C dispatch rules. C passes618;
the isolated old Rust runner passes474; repaired Rust passes618 with equal raw
output. See [literal contracts](../../tests/fixtures/c312-select-header/README.md).

`c312-chain-control-wire` adds E67:719 CCID/WebUSB/NFC cases for GET RESPONSE
and SELECT during a FIDO input chain, malformed/extended envelope admission,
empty CBOR APDU status and recovery. Partial CBOR schemas resume after preserved
controls; successful SELECT and malformed NFC explicitly cancel them. The
portable generator derives expected bytes from pinned C dispatch rules.
See [chain contracts](../../tests/fixtures/c312-chain-control/README.md).
PIV/unselected guard cases retain blanket extended rejection versus the global
GET RESPONSE route under both recognized CLA values.
Broader inline boundaries, pending/config transitions, physical acceptance and
the remaining source audit are separate.


`c312-chain-encoding-wire` adds E68:461 literal mixed short/Case2E/Case3E/Case4E
input-chain cases. WebUSB continues matching input; NFC extended MSG starts a
new request under CLA80/90, including empty Case2E. Finite Le and GET RESPONSE,
255/256/279-byte inline bodies, NDEF UPDATE cursor/readback, CCID extended
rejection/short retry and fresh-request recovery are checked. Old Rust passes194;
unchanged C and repaired Rust pass461.
See [encoding contracts](../../tests/fixtures/c312-chain-encoding/README.md).


`c312-nfc-rejection-wire` adds E69:980 literal NFC large-envelope state contracts.
Five real prior contexts cover partial/complete FIDO input, finite-Le GetInfo,
NDEF UPDATE and OpenPGP certificate/PW3. Ten headers, Lc280/1296/1297, six
valid/malformed envelope forms and split/repeated RF blocks verify C prefix
refusal versus malformed cleanup. Literal default blob byte80, GetInfo map21,
contiguousabcd readback and PIN query prove retained input/output/cursors and
authorization. Fresh FIDO requests prove recovery. C980, old Rust430, repaired
Rust980. See [rejection contracts](../../tests/fixtures/c312-nfc-rejection/README.md).
