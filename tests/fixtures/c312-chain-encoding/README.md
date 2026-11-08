# Mixed APDU encoding and input chains (E68)

Generate the literal vectors with `tests/support/c312_chain_encoding_vectors.py`.
Expectations follow pinned C `src/apdu.c`'s FIDO input and NFC extended reset
rules, and NDEF's UPDATE cursor; they are not derived from runner output.

WebUSB's bounded extended frames continue matching FIDO chains. Each NFC
extended MSG starts fresh, including an inline CLA90 fragment or empty Case2E.
The matrix uses short, Case3E, Case4E Le0000 and Case4E Le1 fragments at each
split of a valid largeBlob request. Literal default byte80 proves complete
semantic parsing, and finite-Le response continuation is checked explicitly.
Unknown commandff exercises255/256/279-byte inline bodies. Actual NDEF UPDATE
fragments prove that extended admission also preserves non-FIDO write cursors.
CCID still rejects extended input before routing; retrying as short proves the
pending input survives rejection. Fresh subsequent commands verify cleanup.

Run `c312_ccid.py` against a separate clean pinned C checkout and the Rust
`nfc-wire-image`, or run host CTest `c312-chain-encoding-wire` for Rust alone.
These are composed host wire contracts, not physical RF/USB or stack evidence.
