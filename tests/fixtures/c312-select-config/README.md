# Disabled-applet SELECT contracts

E65 has340 literal cases on real CCID, WebUSB and NFC transports. All policy
changes use authenticated Admin APDUs, with exact six-byte configuration
readback. A disabled OpenPGP SELECT establishes an unselected context without
fixture state injection. Other prior contexts are authenticated Admin and,
when enabled, FIDO.

Targets are NDEF, OpenPGP, FIDO and the full/9-byte/5-byte PIV AIDs. CCID covers
short Case3/4; WebUSB/NFC additionally cover extended Case3/4. Valid P2 and P2FF
check that P2 rejection precedes disabled-target handling. Each case checks
selection/grants, absence of stale GET RESPONSE, Admin PIN retry status, config
restoration and successful FIDO SELECT/VERSION recovery.

The C distinction is deliberate: disabled NDEF follows unknown-AID rejection,
which revokes USB FIDO only and preserves NFC FIDO or unrelated Admin grants.
Other disabled applets call disabled_applet_response and clear selection on
all transports. An invalid P2 never enters either disabled-target branch.

Pinned C passes340. Old Rust passes326, failing ten Admin-retention cases and
four NFC FIDO-retention cases for disabled NDEF with valid P2. The repaired
Rust branch passes all340 with identical raw outputs. This suite does not
establish broader CLA/P1, malformed extended envelopes, physical RF or complete
source-audit acceptance.

From the Core root:

```sh
python3 tests/support/c312_select_config_vectors.py \
  --output tests/fixtures/c312-select-config/vectors.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/separate-c-build \
  --rust-runner /path/to/full-nfc-usb-session-runner \
  --vectors tests/fixtures/c312-select-config/vectors.json \
  --output tests/fixtures/c312-select-config/report.json
```

CTest c312-select-config-wire requires CTAP/PASS/Admin/NDEF/OpenPGP/PIV. It
replays the same literal Rust expectations without the external C checkout.
