# NFC extended response-file faults

`report.json.gz` contains72 pinned-C and90 Rust independent checks,24/30 per
encoding: Case3E, Case4E Le257 and Case4E Le0000. Decompress with `gzip -dc`.
The additional Rust cases exercise ML-DSA-44. These counts are separate from
literal C/Rust equality vectors.

CTAP requests carry a valid unknown300-byte CBOR field, forcing Lc beyond279
and actual NFC PKE request staging. U2F extended requests stay inline-sized.
MakeCredential, largeBlob and U2F registration responses inject negative,
zero-byte and one-byte reads at two source positions. Each failure probes
GET RESPONSE before replacement and independently verifies successful recovery.
Finite Le limits each aggregate to257 data bytes; the other encodings hide
internal GET RESPONSE chunks until terminal status.

Generic failed reads emit no bytes from that source chunk. Previously sent
250-byte chunks can remain in the terminal6900 aggregate. Every visible blob
prefix is compared with independent expected bytes, including poisoned unused
read suffixes. ISO U2F retains its bounded partial-progress policy.

On first/final RF response packets, same-BN NAK retries cached bytes. An
opposite-BN NAK requests current-BN ACK without advancing the source; a later
same-BN NAK repeats that ACK. Fault status before/after each control exchange
proves it performed no further source read. Retries after completing a response
retain the final packet cache.

Five companion E60 vectors in `c312-nfc` cover these Rules11/12/13 and ignored
unsolicited ACKs, retained selection/input, and empty repeated chained input.
The preceding Rust runner fails all five; unchanged pinned C and repaired Rust
pass all five with identical24 response events.

This is actual host NFC facade/Core execution with injected storage capability
faults. Physical RF/WTX, arbitrary IRQ/cancellation, native file-operation fault
breadth, runtime stack/PKE and full source audit remain open. Reproduction is in
the [testing guide](../../../docs/testing/README.md).
