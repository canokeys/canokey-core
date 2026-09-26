<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust virtual card

The `fido-hid-over-udp` executable uses the production Rust CTAPHID mailbox,
execution/framing engine, APDU engine, shared session/workspace and all applets.
The host crate supplies UDP, a simulated touch input/PKE scratch area and durable
host records. Native inputs are the POSIX signal shim, host crypto and the same
key/digest/PIV crypto adapters used by firmware. No C applet or protocol engine
is linked. This host-only crate uses `std` and must never enter firmware.

Build from the core repository with the pinned Rust toolchain, CMake, native C
compiler, OpenSSL and PC/SC development headers installed:

```sh
rustup toolchain install nightly-2026-09-04 --profile minimal
python3 -m venv .venv-host
.venv-host/bin/python -m pip install -r rust/core/tests/requirements.txt
cmake -S . -B build-host -DVIRTCARD=ON \
  -DPython3_EXECUTABLE="$PWD/.venv-host/bin/python"
cmake --build build-host --target fido-hid-over-udp
ctest --test-dir build-host -R '^virtual-' --output-on-failure
```

The full APDU replay host build also includes this tool and its tests.
`BUILD_TESTING=OFF` omits regression targets without removing either host tool. During
removal of the old C unit suite, `ENABLE_TESTS=ON` builds this Rust UDP executable
alongside the remaining C tests; that does not make those tests Rust coverage.
The PC/SC IFD library also uses this crate.

## Compatibility and storage

- UDP receives reports on port 8111 and sends 64-byte reports to localhost:7112.
  Receive polling continues inside Rust presence/crypto callbacks, with Rust
  owning busy, keepalive, cancellation, INIT resynchronization and mailbox state.
- `CANOKEY_VIRT_LFS_ROOT` retains its name and default path
  `/tmp/canokey-fido-hid-over-udp-lfs-root`, but selects a **host record image**,
  not a LittleFS image. Use a separate path when retaining old C test data.
- `CANOKEY_VIRT_RESET_STORAGE` defaults to `1`, as before. Set `0` to keep
  credentials/configuration across process restarts. A missing image is created;
  a malformed/old image with reset disabled is rejected without modifying it.
- New images are provisioned through Rust ADMIN/OATH APDUs with the existing
  public throwaway attestation key/certificate and the `abc` HOTP credential.
  The intended keyboard default is explicitly set to slot 1 with valid P1/P2;
  the old fabrication code sent zero P1/P2 and ignored its failure.
- `CANOKEY_VIRT_NFC=1` simulates contactless presence policy while using UDP as
  the test transport. It does not simulate the NFC block/chip layer.
- `/tmp/canokey-test-up` remains the touch counter. A negative value suppresses
  simulated touches; nonnegative values permit prompted short gestures and count
  their rising edges. Startup resets this file to zero, as before.
- The existing 64-byte MAGIC REBOOT datagram cancels live execution, then resets
  authorization and the power-on clock **after callbacks unwind**. It reloads
  durable records/configuration and drops transient staging/error injection.
- The existing error-injection prefix followed by operation `0` (write) or `1`
  (read), suboperation `0`, and a filename injects one matching record failure.
  Names follow the Rust ABI: two lowercase hexadecimal digits (`4f` is the CTAP
  counter), with `E103`/`NDEF` exceptions. Legacy C record names do not identify
  the new layout.

The `CKRHOST1` image uses big-endian record lengths and bounded records; writes
sync a private temporary file, atomically rename it and sync the parent directory.
Any uncertain host I/O commit disables storage until reopen. Staged objects are
not published until commit. This is host persistence/error-path coverage, **not**
LittleFS power-loss, device capacity, physical presence or hardware acceptance.

`virtual-hid-udp` independently verifies real credential signatures, durable
counter/RK behavior across process restart, read/write injection, runtime cancel,
INIT and reboot during presence waits, plus NFC presence policy. `virtual-storage`
checks atomic record/staging semantics, rejected images, bounds and fail-closed
commit errors. Fixed ports and the touch-counter file require serialized runs.

The files in `fixtures/` are the publicly known test material from the former
`virt-card/fabrication.c`, not production secrets. Never provision them on a
production authenticator.


## PC/SC IFD library

`libu2f-virt-card.so` now uses the same Rust core and durable host backend. The
native shim uses the system `ifdhandler.h` ABI (including Linux/macOS DWORD width)
and translates IFD constants only. Build with `--target u2f-virt-card`; existing
`test-via-pcsc/pcscd-reader.conf` remains the daemon configuration. Install
`libpcsclite-dev` on Debian/Ubuntu, or specify `PCSC_INCLUDE_DIR` when the headers
are outside the compiler's normal search path. Header availability is required,
not a reason to silently omit the driver.

All driver entries that access the core are serialized across daemon threads;
callbacks borrow a separate host-state mutex, never reentering the core. The
bound reader/slot is identified by the first open's LUN. T=1 negotiation, ATR,
polling callback and single-slot capabilities remain available. Capabilities,
ATR and transmit responses check caller capacity and never overrun the buffer.
Power-down, warm reset and close remove authorization and response state while
retaining records. Slot resets do not reopen the CTAP power-on reset window.

The default image path remains `/tmp/lfs-root`, overridable with
`CANOKEY_VIRT_LFS_ROOT`; reset/keep behavior uses `CANOKEY_VIRT_RESET_STORAGE` as
above. PC/SC preserves an existing touch-counter file. It reads contactless mode
from `CANOKEY_TEST_NFC`, then `CANOKEY_VIRT_NFC`, then `/tmp/canokey-test-nfc`.
Short and extended APDUs execute through the Rust engine. Normal replies retain
GET RESPONSE chaining; NFC FIDO requests aggregate those chunks up to caller
capacity, preserving the previous IFD behavior. Overflow while producing a
response returns no successful prefix and clears the pending session/response;
an invalid buffer is rejected before executing the command.

Host-only INS `00 EE` with data `12 56 AB F0` reboots the session/power-on clock;
INS `00 EF` injects one record failure (P1 read/write selector, P2 zero, filename
in data). Both parse the shared APDU format, and use the same Rust record names
as UDP injection. These controls are absent from firmware and APDU replay.

`virtual-pcsc` loads the actual shared library and checks ABI buffer bounds,
thread migration/serialization, power/reset authorization, full GetInfo,
extended CTAP input, NFC aggregation, independent credential/U2F signatures,
persistence and injected failures. This establishes the IFD boundary; it does
not substitute for a live pcscd/client compatibility run or physical tests.


An optional live-daemon test is available in `rust/core/tests/pcsc_daemon.py`.
Install `pyscard` in the selected Python environment, then build upstream
pcsc-lite with `--enable-ipcdir=/absolute/private/ipc` (plus the usual host
compiler/flex dependencies). The test verifies that compiled path, creates an
isolated reader configuration and refuses to operate on the system daemon path:

```sh
.venv-host/bin/python -m pip install pyscard
.venv-host/bin/python rust/core/tests/pcsc_daemon.py \
  --daemon /path/to/private-build/pcscd \
  --library build-host/libu2f-virt-card.so \
  --ipc-dir /absolute/private/ipc \
  --client-library-dir /path/to/private-build/.libs \
  --log /tmp/rust-pcscd.log
```

A local pcsc-lite 2.0.3 run passed GetInfo and resident credential creation with
an independently verified assertion through pyscard/python-fido2. This exposed
and fixed the common Rust engine's rejection of the client's default P1=80
NFC polling hint; it now completes synchronously as the C engine did. This
software compatibility result still does not establish physical USB/NFC behavior.
