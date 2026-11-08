# NFC large-envelope rejection and retained state (E69)

Generate with `tests/support/c312_nfc_rejection_vectors.py`. Literal status and
cleanup expectations come from pinned C `interfaces/NFC/nfc.c` prefix/discard
and final-envelope handling, not from runner output.

Five actual prior contexts exercise partial/complete FIDO input, finite-Le
GetInfo output, NDEF UPDATE and OpenPGP certificate-write cursors with PW3.
Ten headers at Lc280/1296/1297 cover rejected commands/response polls, invalid
FIDO parameters, valid staged messages and request-size errors. Case3E,
Case4E Le0000/0001, one/three-byte tails and a missing body byte distinguish
prefix refusal from malformed framing. Additional RF schedules split at every
header/body boundary and repeat chained blocks.

Retained input must finish the default largeBlob read (literal byte80).
Retained GetInfo yields CBOR map21 on its next one-byte continuation. Applet
cursors must produce contiguousabcd; PW3 query must retain its real grant.
Fresh subsequent FIDO requests prove cleanup/recovery. This does not claim all
inline framing, output-source classes, physical USB/RF/WTX or CIU stack coverage.

Run `c312_ccid.py` against a separate clean pinned C checkout and the Rust
`nfc-wire-image`, or run host CTest `c312-nfc-rejection-wire` for Rust alone.
