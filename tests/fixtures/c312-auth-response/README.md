# C 3.1.2 authentication response contracts

The saved report executes the pinned C release and current Rust product through
real CCID, WebUSB, native HID MSG and NFC facades. It contains156 C and180 Rust
contract checks, including Rust's additional ML-DSA-44 operations. These totals
are separate from literal equal-byte wire comparisons: opaque credential
handles, generated keys and random signatures differ.

All attestation and resident material is provisioned through ADMIN/CTAP commands.
Independent Python CBOR/crypto implementations verify packed attestation,
assertion and U2F signatures, management public keys and the exact256/257-byte
ordinary-response boundary. Tests cover250-byte source chunks, finite Le,
native buffered output independent of Le, full native sources, finite/unlimited
NFC extended aggregation, RF frame boundaries and NFC source replacement.

The251..256-byte U2F case deliberately provisions opaque certificate bytes to
exercise source-backed file output below the short-buffer limit. Its signature
is independently verified against the provisioned key; this case does not test
X.509 validity or attestation trust. Other MC cases use a full test certificate.

The Rust USB fixture opts into an explicit raw press/release waveform. NFC's
Device observes the actual transport mode. Core authorization still runs;
there is no injected response, credential record or production bypass.

See the [testing guide](../../../docs/testing/README.md) for the paired command.
The Rust-only `c312-auth-response-wire` CTest reruns independent assertions and
does not claim a fresh C comparison. The separate
[response-file fault matrix](../c312-storage-response/README.md) covers selected
negative/short reads and preserves the unresolved U2F difference. Broader
close/cancellation schedules and physical/resource acceptance remain open.
