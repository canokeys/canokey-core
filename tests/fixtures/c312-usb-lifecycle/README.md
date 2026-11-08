# USB lifecycle and empty native continuation comparison

The33 literal cases execute pinned C and production Rust with the same USB,
CCID and HID events. All302 events have equal output; this is serialized host
integration, not physical USB or arbitrary IRQ acceptance.

- E49: duplicate SET_CONFIGURATION=1 preserves directional endpoint HALT,
  SELECT/PIN, native/WebUSB retained output, fragmented CCID and staged HID RX.
  A superseding SETUP still aborts partial WebUSB bytes without revoking PIN.
  Rust ffi tests separately preserve a pending128-byte bulk TX, mailbox epochs
  and the500ms processing-extension timer across the duplicate request.
- E50: actual0/1 configuration transitions and bus reset revoke authorization
  and close retained output. Generic APDU GET RESPONSE then returns6986;
  native HID MSG returns6D00. Each fixture starts independently.
- E51: without retained native output, CLA00/80 C0 is an unsupported instruction,
  even with nonzero P1/P2. Valid native envelopes include ignored fifth bytes,
  absent Le, finite Le and zero Le. Malformed envelopes return HID ERROR03
  before instruction dispatch. A fully transmitted VERSION leaves no source;
  the following C0 is also6D00. Pending-source parameter precedence and a fully
  drained generated response are not established by these empty-source cases.

The C adapter invokes unchanged device_loop(), including device_usb_service().
The Rust adapter calls production USB service before polling CCID/HID/WebUSB.
RESET models hardware FIFO/stall clearing separately, then invokes the actual
bus-reset callback. Direct CCID/HID OUT injections still bypass C class callback
readiness gates. No reset-during-service/IRQ or withheld-HID-IN claim follows.

Reproduce from Core with separate pinned C Core a349b268e12953dd85169e9649091c4f91ce7c68:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-usb-sessions/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-usb-lifecycle/vectors.json \
  --output tests/fixtures/c312-usb-lifecycle/report.json
```

CTest c312-usb-lifecycle-wire replays Rust expectations only. The before-fix
HALT reproduction is archived in the platform lifecycle checkpoint, including
both executable hashes: repeated configuration cleared Rust's HALT to0000,
while C retained0100. Neither feature/layout changes nor hardware flashing are
part of this checkpoint.
