# Platform integration

Hardware ports assemble the Rust facade with board drivers, native crypto,
filesystem callbacks and firmware startup. Current entrypoints and ownership
contracts are documented in [device runtime](device.md), [NFC](nfc.md) and
[architecture](../architecture/README.md). Platforms own their production C
entrypoints and implement Rust capability traits. Optional compatibility
declarations live in `crates/ffi/include/`; native crypto imports have their
own declarations in `crates/native-crypto/include/`.
Use the CIU integration as the current reference. The former C core porting
recipe is preserved only in the historical snapshot and migration guide.

## Release version configuration

A platform may set `CANOKEY_VERSIONS_FILE` to an absolute CMake configuration path
before adding this directory. It must define `CANOKEY_FIDO_FIRMWARE_VERSION` (decimal
uint32), `CANOKEY_USB_BCD_DEVICE` (four BCD digits, e.g. `0x0100`), and
`CANOKEY_CTAPHID_DEVICE_VERSION`, `CANOKEY_PIV_VERSION`, `CANOKEY_OATH_VERSION`
(three decimal bytes each). These independent fields generate `firmware-version.h`
and the CTAP GetInfo constants; protocol versions remain in their implementations.
Missing configuration uses zero versions for development and fails when
`CANOKEY_RELEASE=ON`. Platform Admin strings and release eligibility checks remain
the platform's responsibility. Core commit reporting remains independent.

The PC/SC integration-test simulator is also a platform: CI supplies
`tests/pcsc/versions.cmake` explicitly. Its PIV/OATH compatibility versions
remain `6.0.0`; using the development default `0.0.0` makes external clients
such as piv-go select legacy YubiKey commands and skip supported feature tests.
For a local integration-test build, pass
`-DCANOKEY_VERSIONS_FILE="$(pwd)/tests/pcsc/versions.cmake"` when configuring
from the core repository root. This fixture does not set product release versions.
