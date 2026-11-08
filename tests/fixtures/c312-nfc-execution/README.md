# NFC execution turns and WTX

E63 runs real FIDO GetInfo through the production NFC transport and applet.
Host-only storage hooks forward actual records unchanged, advance the clock,
fire the scheduled production WTX callback and inject reader IRQs. Rust delivers
the matching echo after Io unlock; an early frame finishes before that echo is
armed. The pinned C fixture uses its existing TXEN callback. No transport state,
APDU response or cryptography is substituted.

Eleven normal contracts cover150/151/300ms callbacks, repeated WTX, u32 tick
wrap, early ACK/NAK/deselect/WTX/invalid frames, complete GET RESPONSE and reuse
of selected FIDO state. Each actual TXEN appears in the RF trace; WIRE is only
the last-send summary. Timer cancellation is asserted after Core returns.

Four after-WTX wrong-echo/ACK/NAK/deselect cases have `unresolved` dispositions.
C sends an APDU response; Rust faults/cancels, then sends deferred C2 for
deselect. Passing their observation assertions is not parity approval. These
cases do not close retransmission-cache semantics or physical RF/IRQ timing.

The `c312-nfc-execution` CTest executes Rust assertions. To regenerate paired
evidence with a separate pinned C checkout:

```sh
python3 tests/support/c312_nfc_execution.py \
  --rust-runner /absolute/path/to/nfc-wire-runner \
  --c-repository /absolute/path/to/pinned-c-core \
  --c-build /absolute/path/to/separate-c-execution-build \
  --output tests/fixtures/c312-nfc-execution/report.json
```

`report.json` records the actual runner and fixture hashes. The before/after
checkpoint separately verifies five early-frame failures on the old production
guard using the same corrected fixture. Host scheduling is not board acceptance.
