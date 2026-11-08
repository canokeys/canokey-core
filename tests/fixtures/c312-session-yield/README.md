# Retained applet state and native HID borrowing

`tests/support/c312_session_yield.py` executes real USB CCID/WebUSB/HID facades,
production routing/applets and native crypto. The C runner uses the separate
pinned 3.1.2 checkout. No session, admission or crypto result is replaced.

The 75 checks per side/transport cover preserved PIN and management challenges,
SM2 initiator state with default/custom identity, inline PING lengths
0/57/58/192 and WINK lengths 0/58/192, MSG/CBOR and staged-RX refusals,
malformed short envelopes, interruption/recovery, PIV object writes/reads and
OpenPGP certificate writes/reads. AES proofs and both SM2 roles are checked
independently. The raw trace and APDUs are retained. Random outputs are not
compared byte-for-byte. The old Rust runner fails the SM2 GetInfo busy check.

```sh
python tests/support/c312_session_yield.py --rust-runner /path/to/nfc-wire \
  --c-repository /path/to/pinned-c-core --c-build /path/to/c-build \
  --output /path/to/report.json
```

`c312-session-yield-wire` runs the Rust half in the full host composition.
The separate `usb-sessions` composition holds native HID IN during a competing
WebUSB request, checks rejection and immutable HID bytes, completes HID, then
checks WebUSB recovery with its original PIN grant.
This does not establish physical USB/RF, arbitrary endpoint/IRQ schedules,
all import/decipher continuations, CIU runtime stack/PKE or release acceptance.
