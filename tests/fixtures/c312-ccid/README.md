# C 3.1.2 portable transport vectors

`vectors.json` and the sibling `c312-{nfc,webusb,usb-ownership,hid-ownership,hid-admission}/vectors.json` contain literal packet
bytes, schedules and expected response bytes. Both implementations consume the
same vectors without response normalization. Each case starts a new process
with fresh throwaway storage. NFC input includes placeholder CRC bytes because
the adapters model the chip's successful CRC check.

The C runner compiles unchanged pinned release sources in a separate checkout.
It includes the release's test initialization and replaces only USB output or
FM11NT register access. WebUSB runs the actual EP0 SETUP/OUT/IN/status lifecycle
with16-byte FIFO packets. Rust uses the production CCID/NFC/WebUSB facade, real Core
and applets with the existing test backend. Neither runner substitutes an APDU
parser or applet. Never use `reference/legacy-c` as the C source checkout.

Build the Rust host composition with CTAP, PASS, OpenPGP and NDEF enabled, then
run from the Rust Core root (paths are examples):

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/separate/pinned-c-core \
  --c-build /tmp/c312-wire-build \
  --rust-runner ../build/host-core/tests/usb-sessions \
  --output tests/fixtures/c312-ccid/report.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/separate/pinned-c-core \
  --c-build /tmp/c312-wire-build \
  --rust-runner ../build/host-core/tests/nfc-wire \
  --vectors tests/fixtures/c312-nfc/vectors.json \
  --output tests/fixtures/c312-nfc/report.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/separate/pinned-c-core \
  --c-build /tmp/c312-wire-build \
  --rust-runner ../build/host-core/tests/usb-sessions \
  --vectors tests/fixtures/c312-webusb/vectors.json \
  --output tests/fixtures/c312-webusb/report.json
```

The script verifies the C revision and three dependency pins. It builds with
`-fshort-enums` and asserts the CIU reference request limit is1296 bytes; the
ordinary host enum ABI gives a different key-union size. Reports record source,
adapter, vector and executable hashes and individual results. The adjacent
`.build.log` is generated diagnostic output, not an acceptance artifact.

The current reports cover47 CCID cases/454 steps,60 NFC cases/2566 steps and
28 WebUSB cases/576 steps.
They include short-header discard, error families, bounded extended rejection,
oversized drain/recovery, AIDs, actual NFC inline/staged requests, retransmission,
malformed lengths, finite/absent Le and RF-state reset. PIV GET RANDOM without
Le must return6700; VERSION without Le retains its response behind6103.
Random output and product-specific version bytes are not normalized away;
deterministic cases avoid requesting them.

An `oracle_rows` entry identifies related requirements, not complete coverage of
that row. PKE fault injection, broader response aggregation, WTX schedules,
concurrent endpoint races and physical RF/USB remain separate acceptance.
WebUSB covers its288/289 envelope, transport Hold expiry, last-SETUP timer
semantics and control abort preserving SELECT/PIN, pending responses and FIDO
command chains. That individual fixture does not prove cross-transport C scheduling or physical
EP0 timing. Separate Rust USB-session tests cover an aborted WebUSB reservation
preserving CCID authorization, and pending-response contention after Hold expiry.
The mixed USB ownership fixture adds18 cases/408 events, with CCID_Loop then
WebUSB_Loop once per event and bulk IN completion after observation. It checks
independent EP0/bulk bytes, passive polling, preserved PIN, refused6400 drain,
continuations, invalid power/slot/RFU/length and subsequent recovery. This is
one explicit serialized schedule, not arbitrary IRQ concurrency, HID ownership
or physical USB timing. These runs do not measure CIU runtime stack/resources.

Ordinary CTest uses `--rust-only` and writes reports under the build directory.
That mode checks archived expectations and is explicitly not a fresh C comparison.
Historical Rust extended-CCID success tests remain under
`docs/history/ccid-extended-removed`; they are not current C-alignment expectations.

The HID companion adds21 cases:20 wire-equal cases and one explicitly
unresolved stale-response difference. See its README for IN completion
scheduling and per-implementation literal expectations; do not count that
difference as parity.

The HID admission companion adds28 cases:27 equal-output cases plus one
explicit fresh-state PIN-retry difference. Its README specifies maximum-size
clientPIN fixture provisioning, source exclusion and800/801ms RX boundaries.

The [HID channel companion](../c312-hid-channels/README.md) adds40 cases:
36 equal-output and four explicit CID1 differences. It covers response ownership
across CID changes, WINK payloads, pre-parser framing errors, disabled-WebAuthn
ordering and phase-specific CANCEL. Foreign GET RESPONSE must not expose the
original channel's source even though pinned C permits it.
