# Platform ports

This crate owns the storage, crypto, device and erasure contracts formerly in
`core/src/ports`, and the native implementations formerly in `ffi/src/platform`.
The core reexports these types and retains `forbid(unsafe_code)`. Native C calls
and volatile erasure remain confined to `native/`; key layouts, record IDs,
error mappings, ownership and C signatures have not changed.

`Platform` lends four disjoint capabilities. With `static-backend`, its fields
refer to the concrete native types. This removes vtable loads and passes fewer
arguments through internal helpers without making the core generic over every
capability. With no backend feature, fields are trait objects for mocks.
`dynamic-backend` explicitly overrides `static-backend`, so workspace
`cargo test --workspace --all-features` retains injectable unit-test backends.
The OATH domain uses generic capability arguments with one concrete production
implementation; its domain contracts remain independent of APDU and native ABI.

CIU's staticlib and the CMake host adapter build both enable `static-backend`.
The latter therefore exercises the same direct call paths against the native
host crypto and storage adapters. Run that build separately from the workspace
unit-test invocation: Cargo unifies features within an invocation. The CMake
adapter archive and Rust test targets already use different target directories.

Native storage/crypto/device values require an unsafe constructor at the
serialized FFI composition boundary and are neither Send nor Sync. Safe core
code cannot create an unsynchronized native hardware session. The memory
backend only operates on its caller-owned slice and needs no global state.

The small `native_port!` macro generates inherent methods and forwarding trait
methods from one implementation body. It does not encode protocol policy or
interpret operation tables. Missing-feature defaults still live on the traits;
all supported production compositions supply the enabled methods explicitly.
`MemoryBackend::wipe` is one out-of-line volatile byte loop, also used by local
workspace cleanup that has no borrowed `Platform`.

No native crypto algorithm or optimization flags changed. Direct calls do not
establish on-device timing or total call-path stack usage; those still require
CIU measurements.
