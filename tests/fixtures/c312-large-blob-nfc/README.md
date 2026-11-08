# largeBlobs segmented responses: NFC

E56/C3/T16 executes 11 cases/2478 events through the unchanged pinned C Core
and the production Rust transport facades. USB covers CCID, WebUSB, native
HID CBOR and MSG; NFC covers actual I-block RX, response framing and retries.
Every case starts with fresh virtual storage. Uploads use real CTAP SET
commands; no record, response, parser or crypto result is injected.

The independent generator uses Python CBOR and SHA-256 to construct an empty
array and a4096-byte serialized blob. It exercises1232-byte GET/SET fragments,
file offsets and EOF, prefix/file splits, and Le1/2/3/4/5/249/250/251/255/256.
NFC also tests Le257/1237/65536 and retransmission. Native MSG preserves its
complete-source path when the remainder fits Le, otherwise source chunks cap
at250 bytes. Valid initial HID GET/SET emits processing keepalive BB01;
continuations and invalid requests do not add it. See the literal fixture
for the exact per-transport subset.

The virtual USB fixture acknowledges HID IN during the execution-end wait,
matching the C adapter's transmit-time completion. Only IRQ-side completion
runs during that wait; it never polls or reenters Core. Ordinary withheld-IN
fixtures do not enable this drain. This schedule does not establish concurrent
endpoint, cancellation, physical USB/RF/WTX or CIU stack/PKE acceptance.
Negative/short storage reads and generated MC/certificate/PQ response matrices
remain separate work. Equal-output cases do not approve those paths.

Generate both fixtures from Core:

```sh
python3 tests/support/c312_large_blob.py
```

Execute both implementations with separate pinned C sources/dependencies:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-nfc-wire/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-large-blob-nfc/vectors.json \
  --output tests/fixtures/c312-large-blob-nfc/report.json
```

CTest c312-large-blob-nfc-wire replays Rust expectations only. The archived
report records actual paired execution and hashes, not a CTest parity claim.
