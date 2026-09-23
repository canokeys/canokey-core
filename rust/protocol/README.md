<!-- SPDX-License-Identifier: Apache-2.0 -->
# Common Rust protocol foundation

`canokey-protocol` is allocation-free safe `no_std` Rust without applet, platform
or C ABI dependencies. It belongs to the shared `rust/` Cargo workspace.

## APDU

`apdu/header.rs` defines wire metadata; `decode.rs` implements short and extended
APDU layouts; `chain.rs` tracks logical-command identity and total length without
a payload buffer. The current device profile admits short APDUs and approved
ISO command chaining; syntax support does not enable extended device transport.

`parse()` supplies a borrowed complete-frame view. Production runtime uses
`FrameDecoder::feed_events`, emitting Start metadata before Data slices, then
`finish()` supplies validated trailing Le. Both share the same layout decoder.
The decoder retains seven header bytes and two Le bytes, not the body. Start
metadata has no final Le; its absence must not determine response length yet.
Missing Le, short zero and extended zero remain distinct wire representations.

Frame completion and logical command completion are separate. Chain metadata
can be checked at Start; a failed/truncated frame must then abort the consumer.
An intermediate APDU is acknowledged without finalizing its TLV, hash or object
consumer. Callback slices expire at return. Incremental crypto is permitted;
persistent effects require a command-specific authorization/publication/abort
contract. Do not assume PKE input survives a crypto callback.

## Responses

`Response` owns only continuation metadata. Runtime owns the source handle and
provides a fresh mutable `Source` borrow to each `next`/`clear` call, avoiding
self-referential structs. Reads are monotonic and may return positive short
chunks. Sequential generators need not rewind; the C endpoint retains the chunk
for transport retries. GET RESPONSE never repeats a credential operation.

Completion, failed reads and explicit runtime cancellation close the source
once. Runtime clears pending responses before replacement, reset or handoff;
there is no implicit backend access in Drop. Zero Le makes no progress and
preserves an active response. Errors clear the attempted output range.
The transport owns trailer space and appends SW after payload production.

Source backing must survive incoming APDUs and SW trailer writes. Safe core's
prepared response storage is distinct from the C endpoint buffer. The retained
C boundary ends the RX borrow before starting TX; no C saved-tail implementation
is linked into the independent Rust target.

## TLV

`tlv::Decoder` emits Start/Value/End events and never collects a value. Tags up
to three encoded bytes and definite lengths through 65535 can span arbitrary
input fragments. The internal length state is a Rust enum, not a C-layout struct.
Non-minimal definite lengths remain accepted; indefinite lengths are rejected.
Constructed values are opaque to this primitive: applet schemas own nesting,
container budgets, allowed tags, order and field semantics. OATH's byte-TLV
cursor remains a separate wire format; its properties field is not BER.

Run normal protocol tests from the core repository:

```sh
cargo +nightly-2026-09-04 test --manifest-path rust/Cargo.toml -p canokey-protocol
```

The production runtime's long-command/response scenarios live in
`core/tests/streaming.rs` and run through CTest's `rust-normal` entry.
