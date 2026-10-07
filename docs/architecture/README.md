# Architecture

The root Cargo workspace contains five crates. Keep this granularity unless a
new independently reusable component needs a separately enforced dependency.

| Component | Owns | Dependencies |
| --- | --- | --- |
| protocol | APDU, TLV, CBOR and transport framing/state machines | No applets or native ABI |
| ports | Capability contracts, binding strategy, native implementations | Platform C callbacks at the native boundary |
| core | Applets, authorization, records, shared runtime and workflows | protocol; safe ports contracts and bindings |
| ffi | Pointer validation, serialized runtime access, IRQ/main-loop handoff | core, protocol, ports native adapters |
| host | Host storage and virtual-card composition | ffi, protocol, ports |

`core` is `no_std` and forbids unsafe code. Applet-local wire adapters, services,
record codecs and repositories stay together. Shared mechanisms do not depend
on applets; `flows/` owns explicit cross-applet reset, OATH/PASS binding and
credential-output workflows.
The registry routes operations without absorbing applet policy.

`ctap::Applet` owns the single CTAP/U2F session and response backing shared by
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

| Transport | protocol | core/runtime | ffi/transport |
| --- | --- | --- | --- |
| CCID | Packet fields and framing | APDU/slot state machine and response leases | IRQ mailbox, timed extensions and serialized execution |
| CTAPHID | Report framing and command/error values | Reassembly, channel and execution policy | USB mailbox, progress and shared-runtime arbitration |
| NFC | ISO-DEP block encoding | ISO-DEP state machine, FM11NT I/O policy and provisioning | IRQ/timer handoff, chip callbacks and serialized execution |
| WebUSB | USB setup fields | APDU transaction state; `usb/bos.rs` owns discovery descriptors | EP0 mailbox and shared-runtime arbitration |

`runtime/webusb.rs` owns transactions; `runtime/usb/bos.rs` owns BOS, URL and
Microsoft OS descriptors. The framing crate does not own hardware/session state.

## Ports and bindings

`ports/src/contracts/` defines safe services and value types. `binding.rs`
selects concrete native types for `static-backend`, and trait objects for tests.
`dynamic-backend` wins when Cargo feature unification enables both. Native
callbacks and volatile erasure are confined to `ports/src/native/`.
The core re-exports contracts and selected binding types, not the native module.
The safe `default_memory()` binding supplies erasure for compatibility methods
that have no borrowed Platform; it does not construct a hardware session.

This organization preserves the existing static dispatch and resource behavior.
It does not introduce generic runtime types, heap allocation or another backend
crate. Native constructors for storage, crypto and device remain unsafe and are
used at the serialized FFI composition boundary.

## FFI and native code

`ffi/src/abi/` owns core C entrypoints. `runtime/` integrates device lifecycle
and timers. `transport/` groups CCID, HID, keyboard, USB, WebUSB and NFC facades.
`platform/` assembles the capability bundle. Transport facades manage buffers,
progress and arbitration; credential policy and record interpretation stay in core.

Public C declarations are in `native/include/`. Shared crypto facades live in
`native/crypto/`, filesystem helpers in `native/storage/`. Host-only C entrypoints
are private to `crates/host/native/`. Cryptographic primitives and LittleFS remain
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

Keep authentication, persistent record encodings, retry ordering and wire behavior
unchanged during structural refactors. Platform-specific Flash and stack limits
remain binding; directory organization is not a resource optimization.
