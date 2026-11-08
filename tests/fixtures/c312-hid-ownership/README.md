# Native HID ownership and MSG envelope vectors

Use the [portable runner](../c312-ccid/README.md) with
`--vectors tests/fixtures/c312-hid-ownership/vectors.json`. Ordinary CTest runs
`c312-hid-ownership-wire` against the archived Rust expectations.

Each event polls CCID, HID and WebUSB in the production main-loop order. HID
IN drains to idle within that event: the C sender synchronously waits for IN
completion, while the Rust adapter completes each report then polls HID again.
The C adapter models completion at the transmit hook; it does not replace the
sender or call a substitute TX continuation implementation. All64-byte reports,
including padding and continuation headers, are compared literally. EP0 and
CCID output remain separate observations. This schedule does not test withheld
HID IN, endpoint errors, arbitrary IRQ races or physical timing.

The21 cases include20 with identical C/Rust wire output: fixed native MSG
header/Lc/trailer, absent/zero Le, ignored fifth byte including GET RESPONSE,
malformed envelopes preserving an old continuation, two3000ms delays,
CCID/WebUSB contention, passive CCID queries, busy power, and retained Admin
PIN after unfinished193-byte PING RX and its complete multi-report echo.

One case deliberately records an **unresolved difference**, L8/E35. With a
pending native GetInfo response, a new VERSION causes pinned C to emit the old
GetInfo remainder; Rust returns the new VERSION result. Its `expected_hid_c`
is the complete literal C output, not normalization. The runner requires an
explicit unresolved disposition for this override, reports `wire_equal=false`,
and excludes this case from parity claims. Matching both archived expectations
does not resolve L8 or establish release acceptance.
