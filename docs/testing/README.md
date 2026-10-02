# Testing and host compositions

Run commands from the repository root. Rust unit/integration tests remain under
the owning crate. `tests/integration/` holds Python end-to-end regressions;
`tests/support/` supplies C harnesses and standalone Rust hardware fixtures;
`tests/native/` covers native helpers. Shared external vectors are in
`tests/fixtures/`; Rust-only wire vectors remain beside their Rust tests.

## Prerequisites

Initialize submodules recursively. Install CMake, a C compiler, CMocka, OpenSSL
and PC/SC development headers. Select a Python environment containing
`tests/integration/requirements.txt` using `-DPython3_EXECUTABLE=/absolute/path`.
On Homebrew, pass `-DPCSC_INCLUDE_DIR=/opt/homebrew/opt/pcsc-lite/include/PCSC`
if CMake cannot discover the headers. The root Rust toolchain is pinned.

```sh
cargo test -p canokey-protocol
cargo test -p canokey-rust-core --features admin,pass,oath,openpgp,piv,ctap,ndef
cmake -S . -B build/host -DENABLE_TESTS=ON -DENABLE_APDU_REPLAY=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel 2
ctest --test-dir build/host --output-on-failure
```

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
