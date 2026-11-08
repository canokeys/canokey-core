# Malformed inline NFC envelopes (E70)

Generate with `tests/support/c312_nfc_inline_vectors.py`. ISO short/extended
length rules supply the malformed-envelope oracle before any CLA/INS dispatch.
The five prior contexts are real partial/complete FIDO input, finite-Le GetInfo
output, NDEF UPDATE and authorized OpenPGP certificate writes.

The540 cases include0..3-byte headers, incomplete extended lengths, zero
extended Lc with body, truncated short/extended bodies and excessive Le bytes.
Extended Lc1/2/254/255/256/279 cross the short-buffer/tail boundary. Seven-byte
Case2E is deliberately excluded from malformed truncated-body expectations.
Seventy RF schedules split each header boundary and repeat chained I-blocks.

Malformed requests return6700 and close FIDO input/output. They must not enter
NDEF/OpenPGP command abort or modify their continuation cursors and PW3 grant.
Literalabcd readback, the PW3 query, largeBlob byte80 and subsequent fresh FIDO
commands verify state and recovery. Valid Case2E/3E/4E remains covered by the
existing envelope, mixed-encoding and large-rejection suites.

Pinned C passes540. The saved preceding Rust runner passes334; all206 failures
lose a NDEF/OpenPGP cursor. Repaired Rust passes540 with identical C wire bytes.
The paired report executes production Link/Request/Core/facade code, not a
substitute applet or decoder. Physical RF/WTX, arbitrary IRQ and resource
acceptance remain separate.

Run `c312-nfc-inline-wire` for archived Rust expectations. For a fresh paired
comparison, use `tests/support/c312_ccid.py` with this directory's vectors,
the separate pinned C checkout and the NFC-enabled `usb-sessions-rust` runner.
