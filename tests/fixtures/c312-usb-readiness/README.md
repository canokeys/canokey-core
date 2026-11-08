# USB class readiness and pending native errors

Nine literal cases execute75 events through pinned C and production Rust.
Five cases have equal output; four preserve unresolved L8 output differences.
All expectations are literal; no response normalization applies.

E52 repeats deconfigure/configure and bus-reset/address/configure with main-loop
service withheld. The C adapter calls actual USBD_LL_DataOutStage for CCID
PowerOn and HID PING. Neither request may execute when service finally runs;
a new request after cleanup succeeds. The before.json exploratory capture
records Rust incorrectly executing the queued request at POLL, with both
executable hashes. Its placeholder passed flags are not acceptance results.
Current report.json checks the saved literal expectations against both
implementations. The ffi unit matrix additionally verifies that an intervening
reset invalidates cleanup acknowledgement, blocks TX/RX, and that successful
cleanup rearms each installed OUT pipe once. It is a boundary simulation,
not arbitrary IRQ interruption of actual Provider cleanup.

E53 starts a finite-Le native GetInfo source, then issues C0 with invalid P1,
P2, nonempty body or wrong CLA. C returns the next old GetInfo byte with61ff
and advances its generator; Rust returns6A86/6A86/6700/6E00 and closes the invalid
continuation, so the next C0 returns6D00. These four cases extend L8/E35 and
remain unresolved. A malformed one-byte native trailer instead returns HID
ERROR03 on both implementations and preserves the exact next GetInfo byte.

DEFER suppresses main-loop service/poll for an event. IN still drains per
event; these vectors do not establish withheld-IN, physical USB, arbitrary
IRQ, WebUSB-before-service, or CIU stack/PKE acceptance.

From Core, reproduce using a separate C Core checkout at
a349b268e12953dd85169e9649091c4f91ce7c68 and its pinned dependencies:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-usb-sessions/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-usb-readiness/vectors.json \
  --output tests/fixtures/c312-usb-readiness/report.json
```

CTest c312-usb-readiness-wire replays the Rust expectations only.
