# Native HID response channels

Run the [portable adapter](../c312-ccid/README.md) with
`--vectors tests/fixtures/c312-hid-channels/vectors.json`. Ordinary CTest
`c312-hid-channels-wire` replays the literal Rust expectations. Like the HID
ownership fixture, each event drains HID IN; withheld IN, physical USB and
arbitrary IRQ schedules are outside this evidence.

The40 cases cover same/other-CID CBOR refusal, empty CBOR, malformed MSG,
inline PING and WINK payloads, incomplete inline RX sequence/timeout cleanup,
staged WINK, disabled-WebAuthn ordering with authenticated Admin recovery,
and phase-specific CANCEL. Same-CID CANCEL aborts fragmented RX with sequence
error before parser entry; foreign CANCEL preserves RX and idle/late CANCEL
silently consumes bounded payloads.
Bounded WINK payloads are consumed and ignored as in the C release. Disabled
CBOR/MSG return HID command error before payload validation, including empty
and staged messages; PING and WINK remain available.

Four cases explicitly preserve an unresolved CID1 difference. Pinned C allows
a foreign GET RESPONSE to read and advance the original HID channel's source.
Rust must return busy and retain the original channel's exact next byte. The
foreign request is tested directly and after refused CBOR, empty CBOR or PING.
The last-received CID is not response ownership: the old Rust implementation
also leaked the byte after refused foreign CBOR. The saved before-change
capture demonstrates that case with identical C/Rust output; equality alone
does not establish correct channel isolation.

The current transport binds a continuation to its producing CID when the
final HID report completes. Harmless control traffic and pre-parser errors
cannot transfer that ownership. Reset/INIT still close the continuation.
Neither expected output is normalized; per-implementation literals and the
unresolved disposition remain explicit in vectors/report. This fixture does
not approve a completed intentional-difference disposition or full S4 acceptance.
