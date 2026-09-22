<!-- SPDX-License-Identifier: Apache-2.0 -->
# Common Rust protocol foundation

`canokey-protocol` is allocation-free safe `no_std` Rust with no applet,
platform callbacks or C ABI. `core/` owns session integration; `tlv/` supplies
safe length decoding. The previous C-parser replacement experiment is removed.

## APDU contract

`apdu::parse()` returns a borrowed command view. `FrameDecoder` receives a known
transport frame length and consumes arbitrary packet fragments. Both implement
Cases 1, 2S/3S/4S and 2E/3E/4E. There is no implicit 256/288-byte transport limit
inside the format parser. Length limits and allowed command/transport pairs must
be checked by the integration layer before dispatch.

`CommandInfo::le` records wire absence as `None`, short zero as `Some(256)` and
extended zero as `Some(65536)`. `legacy_le()` reproduces C's implicit maximum Le
for Case 3 and zero for Case 1. Changing that compatibility policy requires a
separate protocol decision. Header recognition of GET RESPONSE matches C
(CLA 00/80, INS C0); it does not itself validate P1/P2 or session authorization.

`FrameDecoder` retains seven envelope bytes and two trailing Le bytes, never the
payload. Its callback receives only data bytes borrowed for that callback.
Callbacks must be free of persistent side effects: frame truncation, cancellation
or callback failure invalidates all provisional semantic state. `finish()` consumes
the decoder. An error poisons it; reuse requires a new instance.

Transport packet fragmentation is not ISO command chaining. `CommandChain`
validates metadata of completed APDU fragments and reports new/restarted/final
commands with a caller-supplied aggregate limit. Matching masks only CLA bit 0x10,
like C. A header mismatch starts a new command, like C. On overflow the Rust
helper explicitly resets, whereas C leaves cleanup to its caller. Consumers must
abort/reset their provisional command state on either overflow or restart.

For ordinary short chained APDUs, first parse the already bounded transport
frame, call `CommandChain::accept`, then feed its borrowed payload to the common
TLV/command consumer. Finish the semantic consumer only after the final chain
fragment. Large standalone source-backed frames use `FrameDecoder` and are
consumed immediately, before crypto, keepalive, storage or session yield can
invalidate their source. This crate does not implement a transport source lease
or allow retaining PKE offsets for later use.

## Response contract

`Response` exclusively borrows a `Source` lease. `next` performs bounded pull
reads, permits positive short reads, tracks progress and emits 61xx until the
final application status. The output slice bounds the chunk size; the transport
owns trailer space and its policy (including the existing 250-byte source chunk
limit). `command` drops the pending stream on a non-GET RESPONSE command and
rejects GET RESPONSE when no stream is active.

Completion, failed reads, explicit clear, cancellation by dropping the response,
or session cleanup must close exactly once. Error output is discarded and the
attempted payload range is cleared. The session integration layer must own and
drop the lease on reset/preemption; no implicit global lock is supplied here.

Intentional primitive-level behavior: zero Le/output capacity returns an empty
61xx response without invoking the reader or advancing; an empty source finishes
without a zero-byte read. Existing C source output can reject a nonempty stream
when its reader returns zero for Le=0. The C adapter deliberately preserves its existing zero-length callback/error
semantics, tested with both backends. The safe Rust lease API keeps its documented
no-progress behavior; it is not substituted for the C callback owner.

Safe source and output borrows are disjoint. The common C adapter retains the
shared-buffer alias and saved-tail machinery, calling Rust only for parsing and
pure continuation arithmetic. In-place moves happen after the Rust input borrow
ends. No overlapping Rust references or long-lived transport pointers are made.
The same production C translation unit is tested with both backends. Response storage must survive
until close; transient request PKE is not a valid response source across crypto.

## TLV contract

`tlv::Decoder` emits Start/Value/End events and never materializes a value. It
accepts up to three encoded tag bytes and definite lengths through 65535, reusing
`canokey-tlv::LengthState`. Indefinite/oversized lengths and unterminated or
oversized tag encodings are rejected. Non-minimal definite lengths remain
accepted for C compatibility. Tags and constructed values are otherwise opaque;
this is not a full BER schema or recursive ASN.1 validator. The applet schema
must check permitted tags, nesting, duplicates, field lengths and values.

Consumers may not retain Value slices. Request errors invalidate earlier events;
`finish` detects truncation, and a failed decoder cannot resume. `write_length`
emits a minimal definite length and leaves undersized output unchanged.

## Normal checks

The normal tests cover a SELECT frame delivered in two transport fragments,
a two-chunk response and a TLV value spanning an ISO command chain. Run with:

```sh
cargo +nightly-2026-09-04 test --manifest-path rust/protocol/Cargo.toml
```

The previous exhaustive and C differential experiment suites are not carried
into this rewrite checkpoint.
