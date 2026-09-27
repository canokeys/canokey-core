# CanoKey Core

CanoKey Core is a Rust implementation of FIDO2/U2F, OpenPGP, PIV, OATH,
ADMIN/PASS and NDEF. It owns applet policy, APDU sessions and transport state
machines. Platform repositories supply hardware drivers and firmware startup.

## Repository

| Directory | Responsibility |
| --- | --- |
| `crates/core` | Safe applets, shared mechanisms, session runtime and workflows |
| `crates/protocol` | Wire formats, parsers and portable transport state machines |
| `crates/ports` | Safe capability contracts, static/dynamic binding and native adapters |
| `crates/ffi` | C ABI, serialized runtime access and hardware-facing transport integration |
| `crates/host` | Host storage and virtual-card integration; private C glue in `native/` |
| `native` | Shared C ABI headers, crypto facades and LittleFS helpers |
| `tests` | Native, cross-language, PC/SC and hardware tests |
| `cmake` | Cargo integration, host profiles and build helpers |
| `tools` | Developer utilities |
| `third_party` | Pinned Git submodules: canokey-crypto, LittleFS and minicbor |
| `docs` | Current architecture, applet contracts, platform integration and testing |
| `reference/legacy-c` | Immutable historical snapshot, excluded from builds |

## Build and test

Initialize pinned dependencies with `git submodule update --init --recursive`.
The root `rust-toolchain.toml` selects the supported Rust toolchain.

```sh
cargo test -p canokey-protocol
cargo test -p canokey-rust-core --features admin,pass,oath,openpgp,piv,ctap,ndef
cmake -S . -B build/host -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel 2
ctest --test-dir build/host --output-on-failure
```

Cargo owns Rust compilation and unit tests. The root CMake entrypoint composes
native dependencies, host executables and cross-language tests. `crates/` has
no independent CMake entrypoint. See [testing](docs/testing/README.md) for
prerequisites, feature profiles, sanitizers and external-client tests.

## Documentation

- [Architecture and boundaries](docs/architecture/README.md)
- [Applet contracts](docs/README.md)
- [Product protocols and compatibility](docs/applets/product-protocol.md)
- [Host virtual card](crates/host/README.md)
- [Contributor instructions](AGENTS.md)
- [Historical snapshot provenance](reference/README.md)

Firmware builds and physical acceptance belong to each platform repository.
Full CIU Flash capacity, runtime stack and physical compatibility acceptance
remain separate migration work; repository organization does not establish them.

Licensed under [Apache-2.0](LICENSE).
