# canokey-ctap

Allocator-free CTAP mechanisms, independent of Core, FFI, native crypto and
product applications. Firmware uses `no_std` without the `schema` feature.

- `config`, `status`, `request`: standard command/status values and exact
  parameterless command admission. `request::credential` owns the streamed
  makeCredential/getAssertion schema and its bounded semantic fields, with
  product capacities, error constants and direct Command publication.
  `credential::borrowed` owns borrowed entities/options/algorithm/list parsing
  over a product reader and extension/algorithm profile. Both use the same root
  label classifier; representation-specific unknown-field/error ordering stays
  explicit. `request::stream`, `agreement` and `hmac_secret` share incremental
  first-error/framing, COSE and encrypted input parsing without crypto or new
  backing. Prepared secrets and product extension engines remain with owners.
- `info`: GetInfo encoding over immutable product policy fragments and a bounded
  synchronous sink. Host-only `schema` compiles supplied fragments; it does not
  read product directories.
- `workspace`: exclusive reservations of existing product backing. Drop erases
  unpublished bytes; publish ends the loan without allocating or retaining it.
- `presence`: synchronous time/touch/progress capability and the two product
  gesture mechanisms. Reset policy and transport ownership stay in adapters.
- `client_pin`: PIN/UV protocols 1/2 key derivation over borrowed SHA/HMAC
  capabilities, extraction-key erasure on every return, and unpadded UTF-8 PIN
  validation by byte and Unicode scalar limits, including encrypted PIN padding
  removal. `client_pin::cipher` shares CBC zero/random-IV framing, borrowed and
  in-place decryption, and prepared output encryption. Products lend existing
  backing and own partial-output erasure on failure. Prepared output permits
  hmac-secret to preserve RNG-before-MAC order without another plaintext array.
  Products retain ECDH, primitive capabilities, durable retry order and token
  lifecycle.
  `client_pin::request` owns ClientPIN command requirements, legacy/scoped token
  admission, permission filtering over explicit product profiles, and exact
  encrypted-field lengths. Adapters select required-first versus scope-first
  error precedence, preserve streaming versus borrowed field admission, and
  supply existing CBOR/status/RP/ownership policy. `client_pin::agreement`
  owns the COSE EC2 field schema and strict borrowed five-field decoding;
  incremental adapters retain ordered optional-field framing and use the same
  field interpretation. Curve membership validation remains in crypto adapters.
- `session`: non-sensitive continuation binding and wrapping idle timestamps.
  Products own cursor secrets, timeout policy, refresh points and reset.
- `provision`, `settings`: attestation read admission, certificate publication
  latch, and the eight-byte SM2 settings codec. Capabilities address only their
  own material; product ADMIN authority and installation policy stay outside.
- `credential`: canonical 34-byte authenticated handle layout, scheme
  discriminators, policy bits and typed HMAC domains. Borrowed transcripts bind
  the ID prefix plus RP and optional SM2 settings for tag/seed derivation, or
  the full ID plus RP for extension keys. Software MACs stream the parts;
  native MACs lend their existing contiguous input buffer. Root provisioning
  and product algorithm support stay with adapters. `Creation`/`Opening`
  share fresh-nonce retries and prepare/compare/cleanup/accept ordering while
  adapters retain seed-before-verify versus verify-before-seed behavior and
  key lifetime/erasure. P-256/SM2 signing seed rejection bounds are shared;
  products decide where the check applies to existing handles.
- `resident`: borrowed CTG1 member decoding, bounded field encoding, UTF-8
  truncation and RP display. `resident::group` validates CTG1 headers and plans
  member offsets/replacement lengths without IO. `group::update` shares no-op,
  same-length patch, variable replacement and deletion across synchronous
  backend capabilities. Constants express buffered peer reads before a staging
  lease versus closed-append streaming, and all-member versus target-only patch
  validation. Products lend existing scratch and retain capacity, preflight,
  atomic commit/abort, recovery status and scratch erasure policy. Credential
  lifecycle uses `credential`. `resident::scan` shares ascending lookup,
  descending discovery, first-empty/replacement selection and counting while
  product readers retain validation, filtering, cache and payload ownership.
  `resident::rp` deduplicates full RP hashes with either a borrowed hash window
  and representative bitmap or incremental visited-slot grouping. Readers retain
  per-pass cache leases; products choose the strategy for their memory profile.
  Management cursor updates, authorization, key derivation and response encoding
  stay with product adapters over shared traversal.
- `response::credential`: classic MakeCredential/GetAssertion reply envelopes,
  complete contiguous assembly with deferred user reads, and staged assembly
  over materialized fields. Authenticator data and certificates may be external
  byte-string bodies; physical insertion markers do not retain a lease or add
  backing. Existing product owners finish/validate the encoder before publishing
  any layout or response. Key creation, signing, PQ framing and commit policy
  remain product engines to migrate.
- `response`: exact/partial certificate window admission. Product backing and
  source close/erasure remain with their owners. General response cursors and
  segmented reads use `canokey-protocol::response`.

`client_pin::agreement` also owns eager/cached generation sequencing and the
validated ECDH-to-protocol-KDF pipeline. Generation candidates and x-coordinate
scratch remain in existing owner buffers; products keep private-key cache,
readiness/publication points, primitive validation/errors and zeroization.

`authorization` owns ordinary MakeCredential/GetAssertion PIN/UV admission:
empty-authentication presence probes, option checks, PIN/always-UV/resident policy
and token admission. Product hooks read policy, service the probe and verify the
existing token; the result retains a product deadline or the bound-session marker.
The explicit silent-secret check order preserves error/read precedence for the
borrowed and streamed schema adapters. Selection and normal UP use the separate `selection` capability; storage and
signing remain product adapters while the full engine is migrated.

`client_pin::operation` owns standard state admission, agreement, authenticated
new-PIN preparation and Set/Change/Token sequencing. Its synchronous backend
lends existing secret/record scratch or uses existing zeroizing value types.
Product transactions retain durable retry/refund timing, policy/deadline checks,
error mapping and token publication; a prepared current verifier is not authority.

`client_pin::response` emits standard agreement, retries and encrypted-token
CBOR fragments into existing product outputs. Core encrypts directly in its
response backing and installs the shared prefix after success; bounded writers
can reject fragments. Products publish only complete replies and retain optional
power-cycle reporting. `agreement` shares the canonical five-field COSE encoder
and structural prefix recognition without conflating peer-point validation.

`client_pin::authentication` verifies a selected SHA-256 prefix using the
owner's existing digest scratch, erasing the complete primitive output before
propagating errors. `client_pin::retry` sequences durable charge before current
PIN comparison and classifies rejection without owning records, secrets or
storage. Product adapters retain restore/policy/deadline and grant commit points.

`client_pin::token` checks permission/RP scope in explicit product-selected MAC
order and provides wrapping lifetime windows and successful-UP permission
retention. It stores no token/secret/session and does not commit usage, RP binding
or cleanup. Products retain expiry origins/limits, error mapping, protocol
admission and the original publication/authority transition points.

No capability retains a product storage/application/transport borrow across
calls. IRQs publish mailbox state; only the serialized owner enters applet code.
The crate adds no complete RX/TX backing or firmware heap. Products need not
install capabilities they do not support (for example vLEI SM2 or streaming
certificate installation).

Run the portable suites without linking a product:

```sh
cargo test -p canokey-ctap
```

`standalone` covers command admission and `get_info` encodes/decodes GetInfo
using only portable dependencies. Other suites check lifetime/erasure, bounded
reads, publication, time policy and fixed product snapshots. These host tests do
not qualify hardware, native cleanup under Linux sanitizers or resource budgets.

`selection` sequences ordinary credential-list selection, exclusion disclosure,
normal presence, successful-UP consumption and response work. `listed` preserves
first-match, parse-tail and inspect-all profiles without owning IDs, keys or
records. Product adapters retain resident scan/count order, silent deadline
checks, storage errors and commit points. The operation is consumed after UP; an adapter may borrow its existing assertion
and publish it into a continuation only after success, without allocating another
session or secret backing. Cancellation during exclusion is mapped by
the product; ordinary presence is never consumed on exclusion or failure.

`response::encoding` owns descriptor/user privacy schemas, COSE EC2/Ed25519/AKP
public-key fragments, management credential envelopes and fixed packed
attestation tokens. Its build script generates invariant CBOR on the host from
portable schema inputs, including optional PQ parameter metadata. Firmware
encodes directly into an existing bounded `Encoder` loan, without a temporary
response. Products retain crypto, dynamic algorithm/SM2 policy, streaming public
key/certificate/signature bodies and publication. `response::auth_data` shares
WebAuthn flags/offsets and RP/counter/attested headers over the existing buffer.
The vLEI Writer loan advances by the emitted prefix even on failure so its
existing rollback owner can erase provisional output. Installing these encoding
capabilities does not install algorithms or change advertised product features.
