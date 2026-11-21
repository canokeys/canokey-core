# Architecture

The root Cargo workspace contains eight product crates and the test card crate.

| Component | Owns | Dependencies |
| --- | --- | --- |
| protocol | Wire encoding and parsing for APDU, TLV, CBOR and transport frames | None in production |
| ctap | Product-independent CTAP parsing, schemas, streaming and sessions | protocol, ports, minicbor for schema and code generation |
| transport-runtime | Transport engine and CCID, CTAPHID, NFC and USB state machines | protocol |
| ports | Capability contracts and backend binding | None |
| core | Applets, authorization, records, session routing and workflows | ctap, transport-runtime, protocol, ports |
| ffi | Pointer validation, serialized runtime access, IRQ/main-loop handoff | core, transport-runtime, protocol, ports, optional native-crypto |
| native-crypto | Native cryptographic imports and capability adapters | ports contracts and C primitives |
| host | Host storage and virtual-card composition | ffi, core, native-crypto, protocol, ports |
| `tests/card` | Test card and regression fixtures | core, protocol, ports, native-crypto, optional ffi |

`core` is `no_std` and forbids unsafe code. Applet-local wire adapters, services,
record codecs and repositories stay together. Shared mechanisms do not depend
on applets; `flows/` owns explicit cross-applet reset, OATH/PASS binding and
credential-output workflows.
The registry routes operations without absorbing applet policy.

`crates/ctap` defines the reusable CTAP contracts. The applet at
`crates/core/src/applets/ctap` applies product policy, manages storage and owns
the single CTAP/U2F session and response backing shared by
native HID and APDU transports. `ctap/apdu.rs` handles FIDO SELECT and command
envelopes; `ctap/message.rs` handles HID MSG envelopes and continuation. Neither
adapter reserves a second session or response buffer. ADMIN invokes typed CTAP
provisioning/settings services; the certificate transaction owns its complete
begin/append/commit/abort lifecycle.

Runtime validates factory-reset presence, inhibits keyboard output and revokes
sessions. `flows/factory_reset.rs` then owns the persistent sequence: NDEF, CTAP,
PASS, OATH, OpenPGP, PIV, and ADMIN PIN recovery last. Failure stops later phases;
this sequence is not an atomic transaction across all records. OATH/PASS flows
unlink references before deleting credentials and bind HOTP using metadata only.

Presence hooks report an attempted wait or poll, including timeout/cancellation.
Runtime consumes `take_presence_attempt()` to prevent the same input epoch from
producing PASS output. Product feature names and consumer feature guards remain
intentional composition/code-elimination choices.

## Transport ownership

| Transport | protocol | transport-runtime | ffi/transport |
| --- | --- | --- | --- |
| CCID | Packet fields and framing | APDU/slot state machine and response leases | IRQ mailbox, timed extensions and serialized execution |
| CTAPHID | Report framing and command/error values | Reassembly, channel and execution policy | USB mailbox, progress and shared-runtime arbitration |
| NFC | ISO-DEP block encoding | ISO-DEP state machine, FM11NT I/O policy and provisioning | IRQ/timer handoff, chip callbacks and serialized execution |
| USB and WebUSB | USB setup fields | USB control and lifecycle state machines | EP0 mailbox and shared-runtime arbitration |

Core composes the portable engine with applet routing and policy.
`crates/core/src/runtime/webusb.rs` owns WebUSB APDU transactions and
`crates/core/src/runtime/usb/bos.rs` owns BOS, URL and Microsoft OS descriptors.

## Ports and bindings

`ports/src/contracts/` defines safe services and value types. `binding.rs`
defines `Platform<'a, B>` with four disjoint capability borrows. `Backends`
and `BackendTypes` carry storage/crypto/device/memory types through static core
routing. Core APIs accept a generic family and re-export contracts plus Platform;
they do not select native adapter types. Rust fakes can compose concrete families.
CIU and host select their own Providers for installation and transport execution.
CIU also owns `ck_device_main`, selecting the same Provider for boot, keyboard,
NFC, serial and cooperative progress. The optional FFI `native-platform`
projection selects native callback imports for explicit storage fixtures, without
exporting a C API. It uses concrete aliases for `static-backend` and trait objects
for dynamic binding; `dynamic-backend` wins when feature unification enables both.
Device and storage adapters belong to CIU, host or this fixture projection.
Native crypto adapters belong to `native-crypto`. The portable `Polling` state machine stays in ports contracts;
the actual presence latch belongs to each outer device adapter.
Portable volatile erasure lives in `ports/src/memory.rs`.
The safe `default_memory()` binding supplies erasure for compatibility methods
that have no borrowed Platform; it does not construct a hardware session.

Firmware retains static dispatch without heap allocation or additional buffers.
Runtime methods are generic over the capability family, while stored applet and
transport state remains backend independent. Native constructors for storage,
crypto and device remain unsafe and are
used at the serialized outer composition boundary.

`composition::core::with_core` is an unsafe shared-runtime entrypoint. Its
caller must serialize all Core access, retain the installed Provider, and
exclude recursive entry from the closure or progress callbacks. Safe applet
tests instead own a local `Core`; they do not borrow the global runtime.

## FFI and native code

`ffi/src/runtime/` integrates device lifecycle
and timers. `transport/` groups CCID, HID, keyboard, USB, WebUSB and NFC facades.
`platform/` assembles the capability bundle. Transport facades manage buffers,
progress and arbitration; credential policy and record interpretation stay in core.

Native callback imports and generated C contracts are in `crates/ports/include/`. Production
entrypoints and their generated header belong to the platform. Native crypto
imports and declarations are in `crates/native-crypto/include/`. C crypto
facades live in `native/crypto/`, filesystem helpers in `native/storage/`, and
C support headers in `native/support/include/`. Host-only C callbacks, including
the POSIX-cancellable PC/SC wait, are private to `crates/host/native/`.
Cryptographic primitives and LittleFS remain
pinned submodules; neither C applets nor the historical transport stack are linked.

## Resource and lifetime contracts

One session owns transient applet state across CCID, HID, WebUSB and NFC.
Large command/response data is streamed; do not add per-applet maximum buffers.
PKE staging is valid only until a potentially clobbering crypto/progress operation.
Parse input and preserve only bounded semantic state before yielding, waiting
for presence or invoking crypto. Response streams release leases on completion,
replacement, failure or reset. USB interrupts queue events; only serialized
main-loop code enters the runtime. Reset invalidates generations without freeing
memory still borrowed by an active operation.
After global USB reset/reconfiguration, data callbacks and submissions remain
closed until serialized reset service acknowledges the current mailbox generation.
A reset during cleanup invalidates that acknowledgement. Service rearms OUT
reception once. WebUSB command SETUP follows the same readiness gate; status
and standard EP0 enumeration remain independent of application admission.
Response fetch also requires readiness. Global reset retains nonexecuting
WebUSB status until serialized class initialization, without exposing old bytes.
Executing calls are cancelled immediately and cannot publish their old result.
Local EP0 failures/reset remain distinct from global lifecycle initialization.

Keep authentication, persistent record encodings, retry ordering and wire behavior
unchanged during structural refactors. Platform-specific Flash and stack limits
remain binding; directory organization is not a resource optimization.

## Native adapter selection

Core depends on ports with default features disabled. Rust test compositions
use capability contracts and depend directly on the `canokey-native-crypto`
crate for C primitives. Ports has no native adapter dependency. CIU selects
crypto capabilities explicitly and implements device/storage traits in its own
crate. The FFI
device/storage fixture adapters compile only for `native-platform`
or unit-test substitution. Host and test-card compositions select their own
native crypto capability without routing through a ports adapter.

## Product request limits

`canokey-ports::RequestLimits` carries static logical CTAP and native HID MSG
budgets. CanoKey defines its 1296-byte profile in `crates/core/src/config.rs`;
`canokey_ctap::config::RequestConfig<L>` derives the GetInfo `u16` value, CBOR
parser budget (one less than the command-plus-CBOR limit), and owned algorithm
capacity. GetInfo code generation, CTAP parsing, PC/SC admission and transport
fixtures consume that profile. HID scratch adapters select a profile through an associated
type; available staging capacity is checked separately. This allocates no extra
request buffers. The shared protocol crate retains only wire framing limits.

A different product may implement a 2048-byte profile without changing HID wire
code. Derive parser and advertised limits through `RequestConfig` and use the
same logical request budget for CTAP HID and APDU chain admission; physical
staging capacity is checked separately. This does not authorize CCID extended
APDUs. Response and application-specific native-message budgets remain separate.

The owned parser reserves one algorithm slot per conservative 20 wire bytes.
A minimal complete public-key parameter map is 22 bytes, so that capacity cannot
fill before the message limit. The divisor preserves existing capacities of 64
at 1296 bytes and 102 at 2048 bytes. Borrowed parsers do not allocate that array.
