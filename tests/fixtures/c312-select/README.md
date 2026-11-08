# SELECT routing, rejection and recovery

E64 has285 literal cases across real CCID, WebUSB and NFC transports. It
checks canonical and opposite-transport FIDO AIDs, ten lengths0..255, eight
single-byte mutations, representative invalid P2 values, truncated Lc17 and
extended SELECT bodies17/279 on WebUSB/NFC. Each case starts with no selection,
FIDO selection or authenticated Admin, then checks routing/grants, absence of
stale GET RESPONSE and recovery through a fresh FIDO SELECT and VERSION.

Pinned C passes all285. The prior Rust implementation fails56: an AID beyond
its16-byte window returned early, bypassing USB FIDO deselection or overriding
P2's6A86 with6A82. Rust now drains an unmatchable AID without expanding the
window, then applies P2 and rejection effects only after the full frame passes
structural validation. Truncated envelopes still return6700 and preserve the
previous context. Rejected NFC SELECT preserves FIDO; rejected USB SELECT
revokes it. Unrelated Admin authentication remains valid.

Core tests additionally cover every P2 byte at lengths16/17/255 for each APDU
owner (2304 combinations), and complete/truncated requests fragmented at1/16/
64 bytes (144 combinations). These are routing checks, not physical acceptance
or exhaustive CLA/P1/configuration mutation coverage.

From Core, regenerate the literal input independently of either executable:

```sh
python3 tests/support/c312_select_vectors.py \
  --output tests/fixtures/c312-select/vectors.json
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned-c-core --c-build /path/to/separate-c-build \
  --rust-runner /path/to/nfc-enabled-usb-session-runner \
  --vectors tests/fixtures/c312-select/vectors.json \
  --output tests/fixtures/c312-select/report.json
```

CTest `c312-select-wire` replays the Rust expectations. The paired report
records both implementations without normalization. Prior failures, patches,
runner identities and product measurements live in the platform checkpoint.
