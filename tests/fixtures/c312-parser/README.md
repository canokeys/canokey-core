# Pinned C CTAP parser executions

`tests/support/c312_parser.py` builds a separate adapter against unchanged Core
`a349b268e12953dd85169e9649091c4f91ce7c68` and its pinned dependencies. It reuses
the existing C test filesystem/crypto initialization. No legacy snapshot is
compiled. Run with the Python environment used by host CTest:

```sh
python tests/support/c312_parser.py --c-repository /path/to/pinned/core \
  --c-build /path/to/separate/build
cargo test -p canokey-rust-core --features ctap cbor_skip_tests
```

The445 vectors execute MakeCredential, GetAssertion, clientPIN, credential
management, config and largeBlobs through both contiguous and external-source
parsers. They cover unknown-value nesting0/1/3/4/5/8/9; long text/byte values;
1240-byte strings exceeding the former1232-byte window; credential-map labels
at31/32/33/256 bytes; matching long-label prefixes; and malformed strings/values.
Credential management includes syntactic auth fields because C checks their
absence inside its parser while Rust checks it later during execution. These
are schema comparisons, not authorization/crypto execution equivalence.

The generated Rust fixture checks each status at every two-part split, with an
empty intermediate consume, and byte by byte. It found and fixed Rust rejection
of long unknown credential labels and missing map-wide RP/text and options/bool
checks. Equal-length long unknown names are skipped as in C without storing
their full spelling; bounded labels retain exact ordering checks. UTF-8 and
body completeness are still validated by Rust's decoder.

The2399 fault/cancellation runs inject one failed read, cancellation with a
failed/successful read, or cancellation before parsing. All1610 cancellation
cases return0x2D, including malformed bodies. C returns success in102 one-shot
read-failure cases; this result is preserved, not used as a fail-closed oracle.
Rust source-error/cancellation integration needs separate transport evidence.
Base-offset3 and callback bounds are asserted. Parser source close/release is
owned by dispatch and is outside this adapter's acceptance scope.

Each of the two runner invocations additionally executes the unchanged C exact
RP regression: four parser/response cases per invocation, eight total. It tests
254-byte RP IDs with equal stored ellipsis/suffix bytes and opposite disclosure
decisions. Rust's independently verified host APDU test additionally checks
first-byte and suffix mutations and signed RP hashes. The C and Rust response
tests use independent fixtures, not byte-identical randomized attestations.

`report.json` records3289 parser executions, raw outcomes, source/adapter hashes
and the runner hash. These results are separate from the twelve USB/NFC wire
suites and establish no physical RF/WTX, USB, CIU stack/PKE or Linux leak result.
