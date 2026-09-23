# Rust CTAP transport slice

The independent `ctap` feature links no C CTAP dispatcher or applet. It is a
**development profile**, not a complete authenticator. It currently supports:

- CTAPHID INIT, PING and CBOR authenticatorGetInfo; capability bits are CBOR and
  NMSG (U2F/MSG is not implemented). WINK and LOCK return INVALID_COMMAND.
- CCID FIDO SELECT (`00 A4 04 00`, AID `A0000006472F0001`) returns `FIDO_2_0`.
  `80 10 00 00` carries CTAP bytes; ISO chaining uses CLA `90` and final CLA `80`.
  GetInfo is command `04`, with no parameters. Unknown CTAP commands return
  CTAP INVALID_COMMAND inside a successful APDU envelope.
- A valid constant GetInfo response, shared by HID and APDU adapters. It
  advertises no resident-key, presence, PIN or algorithm implementation. The
  all-zero AAGUID identifies this unprovisioned development slice.

PIN/UV, credential creation/assertion, U2F, selection/reset and largeBlobs are
not implemented. In particular, CANCEL is silent when idle or still aggregating
fragments; there is no executing asynchronous operation to cancel yet. Do not
interpret successful discovery as successful FIDO authentication.

## Ownership and streaming

`protocol::ctaphid` decodes/encodes only the 64-byte wire layout.
`runtime::ctaphid::Transport` owns CID, sequencing, message length, receive
deadline and response position. `interfaces/rust-core/ctaphid.c` owns endpoint
reports and the ISR/main-loop handoff. USB interrupts never call Rust or PKE.

There is one queued report. While Rust borrows it, USB OUT remains backpressured;
an interrupt arriving during an empty poll must remain queued for the next poll.
The endpoint driver retains another 64-byte RX report; neither buffer is an
entire request. Short requests use a 192-byte inline buffer. Larger requests use
`pke_buffer_read/write`, with a public message limit of 1024 bytes. There are no
transport files, Flash caches, heap allocations or changes to persistent layouts.

Before request staging, the FFI adapter requires CCID to be idle. A CCID session
retains its lease for two seconds after slot power-on or a completed APDU. Only
then may HID reset the old APDU session (including PIN grants and continuations)
and acquire PKE. While HID aggregates or responds, CCID dispatch and keyboard
core calls wait. CCID link interrupts still run. These actual entrypoint gates,
not the PKE owner flag alone, exclude crypto that could clobber PKE.

GetInfo consumes its command byte and releases request storage before preparing
the response. Future parsers must copy needed semantic fields and close the
request before crypto, presence waits or other PKE users. `largeBlobs.set` and
authenticated raw CBOR spans need their own bounded copy/verification schedule.
A source must not become a persistent collection of offsets into PKE.

PING is a transport-only exception: it echoes the staged request in ascending
chunks, without invoking applets/crypto, while retaining exclusive ownership.
The source closes once, after final IN completion or on abort/reset/error. Each
outgoing report remains owned by C until USB completes it; host retries never
repeat source reads or execute an operation again.

Receive timeout is 800 ms since the last packet's **receipt** timestamp, using
wrapping subtraction. Process queued input before checking current time. A foreign
CID gets CHANNEL_BUSY without altering the current transaction; same-CID INIT
resynchronizes it. Wrong sequence, timeout, staging failure and USB reset release
the source. After a one-second IN stall, release the source/session but retain the
submitted report until actual completion/reset. CIU's `FlushEP` is a no-op and
must not be used as permission to overwrite endpoint-owned bytes.

## Code layout

- `applets/ctap/mod.rs`: shared CTAP request state, commands and execution.
- `applets/ctap/apdu.rs`: FIDO SELECT, APDU admission and response backing.
- `runtime/ctaphid.rs`: HID channel/fragments and request/response lifetime.
  Initialization, packet receive, completed-request execution and transmit are
  separate operations. One storage state tracks released, inline or PKE input.
- `interfaces/rust-core/ccid.c`: CCID framing and endpoint handoff; both queued
  late packets and clock expiry use the same receive cleanup.
- `protocol/cbor.rs`: transport-independent incremental structure decoder.

## Request parsing and CBOR

HID and APDU use `ctap::Request` to consume fragments and produce an owned
`Command` or CTAP error. Only `ctap::execute` handles that result, after the
transport has closed request storage. APDU input abort still preserves pending
response backing. HID reuses its 192-byte inline area as the PKE read window;
there is no second request or stack buffer. PING remains a transport-only echo.

`protocol::cbor::Decoder` is the next schema building block, not yet wired to a
stateful command. It consumes arbitrary fragments, emits scalar/container events
and borrowed string fragments, and retains only a nine-byte header, counters and
UTF-8 state. It accepts one definite-length CBOR value, shortest integers/lengths,
UTF-8 text, byte strings, arrays, maps, booleans and null. A caller-supplied byte
budget and eight-container nesting limit bound work and memory. Floats, tags,
indefinite forms, trailing values and incomplete input are rejected. Consumer
failure is terminal. Events are provisional until `finish` succeeds.

Schemas must enforce supported fields, types, canonical map-key order, duplicate
keys and per-field bounds. They may copy required semantic fields but must not
write storage or perform crypto while consuming provisional events. The decoder
itself neither knows USB/PKE nor preserves offsets for later input rereads.

### minicbor assessment

Reviewed minicbor 2.3.0: `Decoder::new` takes a contiguous `&[u8]`, and `bytes` /
`str` borrow whole values from that slice. Its iterators handle CBOR values, not
refillable transport input. Adapting it directly would require complete input or
value materialization, or a second incremental framing layer. That does not
simplify this device's streaming input path. It is pinned as a **host test-only**
dependency to generate independent CBOR vectors; firmware does not link it.
Its `encode::Write` interface remains suitable for future streaming output, if
measured size justifies it. GetInfo keeps its compact constant encoding.

## Standalone extended FIDO over CCID

After FIDO SELECT, CCID accepts `80 10 00 00 00 LcHi LcLo`, followed by
1..1024 CTAP bytes and optionally a two-byte Le. Lc and Le are big-endian.
This exception cannot start or finish an ISO command chain; other applets keep
short APDUs and chaining. It requires no PIN and writes no persistent state.

The short APDU buffer remains 261 bytes. Larger requests keep the seven-byte
prefix and optional Le in that buffer and stage only the body in PKE. Rust
validates the selected applet, command shape, size and session before PKE is
acquired, closing previous input/response resources first. A virtual input
source joins prefix, body and Le for the existing APDU parser. It closes before
applet finalization, including on read or parse failure.

The CCID ISR queues the endpoint buffer pointer and receipt timestamp. OUT stays
NAKed until the main loop consumes the packet; interrupts never call Rust or PKE.
Header fragments are supported. A two-second receive deadline rejects late
fragments, and errors/reset release staged input. USB connection generations
suppress replies from work interrupted by reset. Keyboard work waits while CCID
owns PKE, and HID waits until CCID is idle.

## Endianness and USB composition

USB SETUP fields and descriptor multibyte fields are little-endian. The USB core
already converts SETUP to native integers: class routing compares `wIndex` and
`wValue` directly, including on CIU BE8. CCID `dwLength` is also little-endian.
CTAPHID CID and BCNT, APDU extended lengths/status words, and CBOR integers are
big-endian on the wire. CID allocation is monotonic within the current boot;
channels are transport labels, not authentication capabilities.

When enabled, HID is interface 0, CCID is interface 1, and optional keyboard is
interface 2. Without CTAP, the existing CCID/keyboard interface numbers stay
unchanged. CTAP enables CCID extended exchange level and a 1043-byte maximum
message (10-byte CCID header + 7-byte APDU prefix + 1024-byte body + 2-byte Le).
Other profiles retain short exchange level and 271 bytes. Short HID transfers are discarded rather than parsing a stale tail.

## Validation

From the core directory:

```sh
cargo +nightly-2026-09-04 test --manifest-path rust/Cargo.toml --workspace --all-features
cmake -S rust -B build/rust-host
cmake --build build/rust-host --target hid-usb ccid-usb
ctest --test-dir build/rust-host -R '(hid|ccid)-usb' --output-on-failure
```

Rust tests cover literal endian vectors, request boundaries, monotonic source
reads, close-once semantics, contention, sequence/timeout/resync and injected
scratch failures. The C adapter test injects an interrupt during an empty poll,
checks pending IN-buffer retention after timeout, and resets during a Rust poll.
The CCID adapter test covers split headers, literal LE/BE lengths, PKE source
boundaries, cleanup, late packets, reset races and HID contention. CBOR tests use
minicbor-generated vectors at every split, one-byte fragments, all truncated
prefixes, malformed canonical encodings, nesting limits and split UTF-8.

In the CIU parent repository:

```sh
cmake --preset devkit-rust-ctap
cmake --build --preset build-devkit-rust-ctap
.venv-hil/bin/python tools/hil/devkit_ctl.py --list
# Flash using the parent AGENTS.md workflow, then:
.venv-hil/bin/python tools/hil/rust_ctap_smoke.py --control <control-port> --output <report.json>
```

The read-only HIL checks run 70 PINGs at 0/57/58/192/193/256/1024 bytes, independently
decode GetInfo with python-fido2, check transport errors and CCID ownership, and
check extended CCID buffer/PKE boundaries through 1024 bytes, asymmetric Lc/Le,
malformed envelopes and chain conflicts, and optionally reset during a PKE-backed
request. They create no credentials or PINs.

## Next migration steps

1. Build clientPIN schemas on the incremental CBOR decoder, copying only needed
   semantic fields. Enforce canonical map ordering, duplicate-key rejection and
   command-specific limits before enabling PIN/UV operations.
2. Introduce native/APDU shared CTAP command state, cancellation and keepalive
   before enabling presence waits or crypto. Preserve the source-close boundary.
3. Migrate clientPIN, credentials/assertions and remaining C commands in measured
   slices, using the shared applet workspace and compact durable records.
