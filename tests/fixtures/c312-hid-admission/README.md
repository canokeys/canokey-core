# Native HID request admission vectors

Use the [portable runner](../c312-ccid/README.md) with
`--vectors tests/fixtures/c312-hid-admission/vectors.json`. CTest's
`c312-hid-admission-wire` checks the archived Rust expectations. Poll order and
per-event HID IN draining follow the [HID ownership fixture](../c312-hid-ownership/README.md).
This is host execution of real state machines/applets, not physical USB or
withheld-IN/IRQ acceptance.

The28 cases include27 with equal C/Rust output:

- The1296-byte limit applies to the complete HID message for PING, CBOR and
  native MSG. Native APDU headers/trailers consume that budget. Reject1297,
  1305 and65535 at the first report, then recover for VERSION/Admin queries.
- Echo all1296 PING bytes; parse a staged malformed1296-byte MSG; execute valid
  clientPIN requests at total1296 via CBOR and MSG with absent/zero Le.
- Refuse new staged PING/MSG/CBOR while a native response is pending, before
  PKE can overwrite it. Inline CBOR is also busy, but empty CBOR is a HID length
  error. Same-CID inline PING and WINK preserve GET RESPONSE.
- Accept a continuation exactly800ms after the last report; expire at801ms.
  Both boundaries are checked across tick wrap with subsequent recovery.

The three successful maximum-size clientPIN cases explicitly set
`ctap_pin_retries=8`. The C adapter calls the unchanged installer and writes
that test attribute before USB starts; Rust's fresh backend already has8.
This is declared fixture state, not response normalization or evidence about
C's retry-counter default.

The remaining case, C1-RETRIES/E39, is explicitly unresolved. Without that
fixture override, a freshly installed C authenticator with no PIN lacks the
retry attribute. Its getPinRetries response encodes LFS_ERR_NOATTR(-61) as a
negative retry count. Rust returns8. Both literal reports are retained, with
`wire_equal=false`; matching their per-implementation expectations is not parity.
The production C sources are unchanged. The adapter's normal USB initializer
now calls ctap_install, matching the existing NFC fixture and Rust product
installation; prior checkpoints retain their original adapters and reports.
