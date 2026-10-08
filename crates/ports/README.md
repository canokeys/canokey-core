# Platform ports

This crate owns the storage, crypto, device and erasure contracts formerly in
`core/src/ports`. Core reexports these types and retains `forbid(unsafe_code)`.
Ports has no native imports. CIU and host own storage/device backends;
`canokey-native-crypto` owns reusable native crypto imports. Portable erasure
operates on its caller-owned slice.

`Platform<B>` lends four disjoint capabilities from a backend family. CIU and
host select concrete `BackendTypes` through their Rust Provider. The default
`DynamicBackends` supports trait-object test compositions. The compatibility
FFI composition's `dynamic-backend` switch overrides `static-backend`; it also
keeps workspace all-feature tests injectable. This supported compatibility/test
use is why the switch remains. Firmware continues to use static dispatch.
The OATH domain uses generic capability arguments with one concrete production
implementation; its domain contracts remain independent of APDU and native ABI.

Cargo unifies features within an invocation. CMake compatibility archives and
Rust test targets use separate target directories to keep their selections
independent. The full feature matrix covers both supported compatibility modes.

Native storage/crypto/device values require an unsafe constructor at the
serialized FFI composition boundary and are neither Send nor Sync. Safe core
code cannot create an unsynchronized native hardware session. The memory
backend only operates on its caller-owned slice and needs no global state.

Missing-feature defaults live on the traits;
all supported production compositions supply the enabled methods explicitly.
`MemoryBackend::wipe` is one out-of-line volatile byte loop, also used by local
workspace cleanup that has no borrowed `Platform`.

No native crypto algorithm or optimization flags changed. Direct calls do not
establish on-device timing or total call-path stack usage; those still require
CIU measurements.
