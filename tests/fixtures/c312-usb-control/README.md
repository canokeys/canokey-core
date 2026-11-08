# USB control request comparison

The 36 literal cases execute the unchanged pinned C USB core and the production
Rust USB facade using the existing WebUSB event adapter. Twenty-nine cases have
equal output. Seven cases retain explicit unresolved differences: five U3
endpoint GET_STATUS validation cases and two U4 busy descriptor cases. Matching
each implementation's own expectation is not wire parity.

E46 exercises HALT and CLEAR_FEATURE on CCID/HID IN and OUT independently,
little-endian status, repeated clear, rejected endpoint/field/state combinations
and recovery. The Rust feature-matrix test additionally checks absent HID and
keyboard endpoints. The ffi mock counts controller calls so clearing an already
clear endpoint cannot skip the driver's DATA-toggle reset command. This verifies
dispatch, not the physical register effect or bus waveform.

E47 records that C accepts an endpoint GET_STATUS with a nonzero high index,
nonzero wValue or wLength other than two and submits two bytes. Rust rejects
these requests. Preserve Rust validation; the release disposition remains open.

E48 compares the same manufacturer string without normalization. While a FIDO
response is retained, C cannot acquire its shared descriptor buffer and stalls;
Rust replies from independent bounded control storage. A new request supersedes
that descriptor transfer and both implementations return the same next FIDO byte
(`b5 61ff`). The configuration case requests only the nine-byte Rust header;
C refuses before descriptor generation. It does not establish full configuration
descriptor equality or approve the difference.

Reproduce from Core with a separate clean checkout of C Core
a349b268e12953dd85169e9649091c4f91ce7c68 and its pinned dependencies:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-usb-sessions/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-usb-control/vectors.json \
  --output tests/fixtures/c312-usb-control/report.json
```

Ordinary CTest replays the archived Rust expectations as `c312-usb-control-wire`;
it does not rerun C. All events are serialized, with explicit EP0 acknowledgements
and no physical USB or arbitrary IRQ acceptance. The shared adapter now services
deferred lifecycle cleanup through C device_loop() and Rust USB service. This
suite's addressed-state cases only deconfigure and test rejection; the separate
c312-usb-lifecycle suite exercises reconfiguration and bus reset.
