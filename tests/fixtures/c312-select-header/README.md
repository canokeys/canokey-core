# SELECT header and envelope contracts

E66 exercises618 literal cases across CCID, WebUSB and NFC. Prior contexts are
unselected, FIDO, authenticated Admin, authenticated PIV/OpenPGP and NDEF with
the CC EF selected. Setup uses real APDUs; disabling OpenPGP establishes the
unselected context while leaving FIDO enabled. No fixture injects applet state.

Short commands cover CLA00/01/10/80/90/FF and P1=00/04/FF. WebUSB/NFC also
cover Case2E and Case4E with Le0000/0001/0100 and malformed one/three-byte Le.
Expectations follow the exact global SELECT discriminator, then C's selected
applet handler, including PIV extended rejection. NDEF accepts all CLA values;
only UPDATE BINARY uses its chain bit. OpenPGP rejects chained SELECT. FIDO
rejects CLA10; proprietary chained fragments acknowledge before terminal INS
validation. The terminal unsupported command must never dispatch CTAP CBOR.

Six additional URL/NDEF schedules reject chained URL, accept a255-byte short
URL and verify contiguous NDEF writes across arbitrary CLA values. The OpenPGP
host helper uses one short APDU for ordinary objects while retaining deliberate
certificate fragmentation.

Each case probes the selected context, retained PIN grant or NDEF EF, absence
of stale response bytes, Admin grant after reselection and fresh FIDO recovery.
Finite Le1 checks the literal55/6105 response before a new command abandons it.
The deterministic generator derives expectations from dispatch rules rather
than copying either runner's output. This is host wire evidence, not physical
RF, pending-operation/config transitions or full source-audit acceptance.

From the Core root:

```sh
python3 tests/support/c312_select_header_vectors.py \
  --output tests/fixtures/c312-select-header/vectors.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/separate-c-build \
  --rust-runner /path/to/full-nfc-usb-session-runner \
  --vectors tests/fixtures/c312-select-header/vectors.json \
  --output tests/fixtures/c312-select-header/report.json
```

CTest c312-select-header-wire requires CTAP/PASS/Admin/NDEF/OpenPGP/PIV and
replays the same literal expectations without an external C checkout.
