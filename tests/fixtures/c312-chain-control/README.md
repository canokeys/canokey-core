# Pending FIDO input-chain control contracts

E67 uses real Admin configuration and FIDO SELECT, followed by ISO command
fragments. Controls cover GET RESPONSE, unknown/invalid-P2/disabled-NDEF SELECT,
successful same-FIDO/Admin SELECT, unsupported commands, malformed envelopes
and extended commands. The generator derives expected bytes from C dispatch
and transport rules; it never reads an implementation's results.

GET RESPONSE without output returns6986 and preserves input. Rejected NFC
SELECT preserves FIDO input; USB rejection revokes FIDO. Successful SELECT
ends the old chain. Malformed CCID/WebUSB envelopes never enter routing;
malformed NFC resets input. Every extended CCID envelope returns6700 without
entering Core. Empty CBOR APDUs return6700; native HID keeps its own CTAP error.
Thirty-six guard cases cover PIV and unselected contexts under CLA00/80:
PIV rejects all extended polls, while an unselected global poll returns6986
on WebUSB/NFC. The complete suite has719 cases, including170 partial-schema
continuations.

Payloads include an unknown command, a wrong-typed largeBlob field, empty input
and largeBlob get1/offset0. The default serialized array's first byte80 makes
the successful CBOR response independently predictable. Multiple split schedules
include empty intermediate fragments and interruption of an incomplete schema,
with the suffix arriving only in the terminal APDU. Recovery checks prove
selection state, absence of stale output and independent subsequent parsing.

From the Core root:

```sh
python3 tests/support/c312_chain_control_vectors.py \
  --output tests/fixtures/c312-chain-control/vectors.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/separate-c-build \
  --rust-runner /path/to/full-nfc-usb-session-runner \
  --vectors tests/fixtures/c312-chain-control/vectors.json \
  --output tests/fixtures/c312-chain-control/report.json
```

CTest `c312-chain-control-wire` replays the same expectations without C. Host
wire tests do not establish physical RF/USB, stack/PKE, all pending CTAP/HID
semantic state, or completion of the source audit.
