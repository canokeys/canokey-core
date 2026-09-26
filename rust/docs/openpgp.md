<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust OpenPGP implementation and normal validation

The optional `openpgp` core/FFI feature registers OpenPGP Card 3.4 at
`D27600012401`. The CIU `devkit-rust-openpgp` and host
`CANOKEY_APPLET_OPENPGP` profiles explicitly combine ADMIN, PASS, OATH and
OpenPGP. PIV, CTAP, NDEF and NFC are not enabled. No legacy C OpenPGP dispatcher,
PIN manager, `src/key.c`, or applet storage layout is linked.

## Responsibilities

All OpenPGP code is under `core/src/applets/openpgp/`:

| Module | Responsibility |
| --- | --- |
| `domain.rs` | Algorithm identifiers, attributes and permitted key roles; no APDU/FFI |
| `protocol.rs` | APDU checks, status mapping and stream lifecycle |
| `service.rs` | Session grants, PIN transitions, key operations, UIF/counter policy; no APDU/SW |
| `key_commands.rs` | Key-command APDU checks, TLV input decoding and public-key response encoding |
| `data.rs`, `encoding.rs` | Data-object schema and bounded BER response encoding |
| `import.rs` | Incremental import schema: bounded envelope/descriptors, direct component writes |
| `pin.rs`, `repository.rs` | Durable retry mechanism and explicit versioned record codecs |

The common protocol crate owns APDU decoding, ISO chaining, BER length decoding
and the only GET RESPONSE cursor. Registry lends one session workspace to the
selected applet. FFI owns native pointers/volatile erasure; safe core forbids
unsafe code. The C primitive adapter has no APDU, PIN or file policy.

## Reading the protocol constants

`wire.rs` names command bytes and data-object tags; `data.rs` contains the
values advertised to host software. The values exclude their outer tag/length
unless explicitly described as a complete TLV. A capability flag is a protocol
promise: changing it requires checking the corresponding command implementation.

| Term | Meaning in this implementation |
| --- | --- |
| Historical bytes (`5F52`) | ISO 7816 card discovery information: card services, selection/chaining capabilities and life-cycle/status bytes. This is not a history of operations. |
| Extended capabilities (`C0`) | OpenPGP feature flags and limits: challenge/import/PIN-mode/algorithm support, byte limits, and unsupported secure-messaging/PIN-block/MSE features. The array in `data.rs` documents each field. |
| AID / DF name | Application identifier used to select the OpenPGP application; DF means dedicated file in ISO 7816 terminology. |
| DO / TLV | Data object / tag-length-value encoding. A tag names a protocol object, not a file offset. |
| PW1 / PW3 / RC | User PIN / administrator PIN / reset code. PW1 has separate signature and other-operation authorization references. |
| UIF | User Interaction Flag: the per-key touch policy and the card's supported input method. |
| SIG / DEC / AUT | Signature / decipher / authentication key roles. |
| CA fingerprint | Fingerprint of a certification-authority key, distinct from a fingerprint of one of the card's own keys. |
| PSO / MSE / SM | PERFORM SECURITY OPERATION / MANAGE SECURITY ENVIRONMENT / secure messaging. This profile implements PSO but advertises neither MSE nor SM. |

`repository.rs` layout constants are byte offsets. Its expanded RAM state has
fixed-capacity fields, while disk encoding omits unused capacity; the two layouts
must not be interchanged. `*_END` denotes an exclusive bound, and `*_MAX` is a
value's byte capacity excluding its length prefix.

## Protocol profile

Commands implemented: SELECT, SELECT DATA, GET DATA/NEXT DATA, VERIFY/logout,
CHANGE REFERENCE DATA, RESET RETRY COUNTER, INTERNAL AUTHENTICATE, PSO signature/
decipher, PUT DATA, IMPORT KEY, GENERATE/READ PUBLIC KEY, TERMINATE, ACTIVATE,
GET CHALLENGE, and CanoKey retry-limit command F2 (a vendor extension, not
part of OpenPGP Card 3.4). ADMIN 03 resets OpenPGP after
ADMIN authentication; the ADMIN factory-reset workflow also resets OpenPGP.

Supported algorithms remain RSA-2048/3072/4096, P-256, secp256k1, P-384, P-521,
Ed25519 and X25519. X25519 is decrypt-role only; Ed25519 is sign/auth-role only.
RSA signatures use PKCS#1 v1.5 and RSA decipher validates v1.5 padding.
Invalid decipher padding returns 6A80; primitive failures retain 6900. Short
Weierstrass digests are left-zero-padded to the native scalar width without
changing their numeric value. Signatures are raw r||s; ECDH consumes the nested
A6/7F49/86 object. OpenPGP X25519 imported scalars are big-endian integers, matching the native
representation (unlike the PIV import convention). Public values and shared
secrets use RFC 7748 little-endian wire order. `key_regressions` verifies the
legacy literal public-key vector as well as independent shared-secret checks.

PW1 defaults to `123456`, PW3 to `12345678`; both start with three tries. Reset
code is initially unset. There is no KDF or enrollment procedure. PW1 grants
81 and 82 are distinct; successful verification of one retains the other.
Wrong verification revokes that PIN's grants. Empty VERIFY queries do not revoke
authorization. Default signing PIN policy consumes grant 81 for one signature.
Retry limits are 1..15; PIN lengths are 6..64 (PW1) and 8..64 (PW3/reset code).
Retries are charged durably before comparison and restored on a correct PIN.

UIF policies 0/1/2, permanent-policy protection and the configured touch-cache
interval are implemented. A fresh successful presence gesture is consumed so
PASS cannot replay it. Cache/grants are cleared on real session reset or applet
switch; reselecting the same AID retains grants. NFC presence is not implemented.

Data objects include AID, historical bytes, cardholder/login/URL/language/sex,
capabilities, algorithm attributes/list, PIN status, key/CA fingerprints, key
dates, key provenance, signature counter, certificates, UIF and cache time.
Constructed GET DATA objects retain their outer BER tag. P1/P2, lengths,
algorithm attributes and UIF indicator bytes are validated against this profile;
legacy permissive parsing is not a compatibility requirement.

The vendor retry command is `00 F2 00 00 03 <PW1-limit> <RC-limit> <PW3-limit>`.
It requires a verified PW3 grant, accepts limits 1..15, resets PW1/PW3 to their
default values, preserves the reset-code value, and revokes session grants.
With authorization established, a body length other than three returns 6700;
an out-of-range limit returns 6A80. A failed persistence update returns 6900
and does not retain the prior grant.
Normal OpenPGP host regression exercises this command with a verified PW3 grant
and verifies the default PW3 afterward.
Crypto failures are reported internally as `Error::Crypto`, distinct from storage
failures; both retain the existing APDU status `6900` (unable to process).

## Streaming and memory

Logical commands support ISO chaining. CCID/NFC also accept extended OpenPGP
envelopes under the existing transport/session and command-size limits; short
commands retain their 261-byte transport frame. Extended GET PUBLIC/GENERATE
with a two-byte control reference is covered by the literal legacy frames and
GET RESPONSE checks. This does not enlarge transport buffers. Request modes are:

- Small commands and irreducible RSA ciphertext: at most 544 bytes in the shared
  session input (including protocol framing), rather than a separate worst-case
  buffer in each applet.
- Certificates: up to 1152 bytes, appended to a dedicated object transaction
  after PW3 authorization. Atomic rename publishes only the final complete
  object; abort/reset leaves the previous certificate authoritative. Reads use
  storage ranges and GET RESPONSE, without a certificate-sized RAM allocation.
- Key import: at most 1400 encoded bytes; only a 48-byte structural prefix is
  collected. Descriptor lengths route each component directly into the shared
  key representation, across arbitrary frame boundaries. No whole encoded-key
  buffer or unauthenticated generic flash RX scratch exists. Final validation
  and publication happen once, after the complete envelope is consumed.

Workspace size is 2360 bytes including alignment: one 1288-byte `KeyMaterial`,
544-byte crypto input and 528-byte semantic output plus small framing. RSA's
native ABI view is checked with C static assertions; storage serializes only its
explicit byte components, never native headers/padding. ECC uses the first 198
material bytes and lends the unused tail to the native signing primitive. The
same arithmetic serves the original entrypoint and the caller-workspace variant.
CRT validation likewise accepts caller scratch. Neither change adds a per-applet
or global worst-case crypto buffer. All material bytes are wiped on completion,
abort and reset; pending response bytes survive until drained or closed.

Large responses retain the computed public key/signature once; GET RESPONSE
never repeats randomness, crypto or signature-counter updates. Metadata is a
bounded BER result; certificate responses are storage-backed.

Native crypto runs synchronously. A C CCID timer emits time extensions during
long key generation. Timer callbacks perform link maintenance only, never enter
Rust, change persistent applet state, or touch PKE. USB reset invalidates the
transfer and main-loop cleanup subsequently revokes the Rust session.

## Persistence and recovery

Records 4..13 map directly to hexadecimal filenames `04`..`0d`. State has
four flags, 60 CA-fingerprint bytes and five length-prefixed variable fields
(70 bytes at defaults). PIN records have four header bytes plus the actual PIN.
Certificates store only their contents. No previous-format decoder is included.
The key record is a 31-byte version/algorithm/origin/UIF/fingerprint/date/counter
header followed by explicit private components. RSA stores exponent4 and five
active-width components: 644/964/1284 material bytes for RSA-2048/3072/4096.
Including metadata, RSA-4096 occupies 1315 bytes. Metadata reads fetch only the
31-byte prefix and check the exact complete record size; the native 1284-byte
key workspace is not a bound on the stored record. Generated and imported
RSA-4096 keys are exercised after host reset for signing, authentication and
decryption in `openpgp-normal`.
ECC stores only its private scalar. A new signing key and its zero
counter publish in one transaction. Successful signing persists its increment
before exposing the response; delivery failure does not roll the counter back.
The 24-bit counter saturates rather than wrapping to zero.

Multi-record reset first marks the applet terminated and clears that marker last;
an interrupted reset remains recoverable with ACTIVATE. Storage failures are
fail-closed (`6900`), never a trigger to format or reinterpret old C records.
`s` is separate from `t` used for atomic record updates.

When the terminated marker is set, SELECT returns `6285` until ACTIVATE
completes recovery. Presence cancellation is reported as `6400`; this is the
Rust profile's explicit mapping for the legacy touch-cancel path.

## Validation scope

`core/tests/openpgp_normal.py` is shared by host and USB runners. It generates
and imports all nine algorithms, uses every permitted role, checks results with
Python cryptography, transfers multi-APDU RSA-4096 templates and 1 KiB
certificates, and exercises ordinary PIN/configuration/reset flows. The host C
primitive port uses OpenSSL independently of the device backend. CTest registers
`openpgp-normal` alongside ADMIN/PASS, OATH and common-runtime tests.

CIU runners: `tools/hil/rust_openpgp_smoke.py` and
`tools/hil/rust_openpgp_persistence.py`. They require a dedicated device with
default PINs, reset OpenPGP initially, and clear throwaway OpenPGP state on
success. Failures retain test state for inspection; they do not erase legacy
files or other applets. Persistence includes real reset and CIU power off/on.
GnuPG card recognition is checked separately with an isolated host configuration.

The initial integration UART stack instrument measured a 5072-byte high-water mark over normal
OpenPGP operations, below the 5120-byte budget, with the original 7680-byte stack
reservation. This is workload evidence, not an exhaustive stack proof. Physical
OpenPGP touch was explicitly deferred by the user; host presence simulation is
not evidence of physical touch. No fuzz, fault-injection or exhaustive boundary
campaign was run. CIU evidence is in `hil-reports/rust-openpgp-20260923/README.md`.

The design-review revision uses domain errors in PIN/repository services and
explicit `RsaPkcs1Sign`, `RsaPkcs1Decipher`, `EcSign` and `Agree` crypto operations.
UIF waits use runtime Request tracking: even a failed wait claims its gesture,
which remains unavailable to PASS until release. Core/FFI `openpgp` alone does
not initialize ADMIN, PASS or OATH; the CIU preset deliberately combines all four.
See `hil-reports/rust-design-review-20260923/README.md` for current resource and
validation measurements; earlier stack evidence is not reused as a new bound.

### Lifecycle cache and uncertain writes

The selected applet caches the durable terminated flag. Install and successful
activation prime it; successful termination records the terminated value.
Reset discards the cache. PUT DATA may replace the shared state record and
invalidates the flag before mutation, as do termination and activation.
Any failed lifecycle write leaves the outcome unknown; the next command reloads
the durable flag and fails closed if that read fails. TERMINATE clears PIN and
touch grants before the write, including when persistence subsequently fails.
The `lifecycle_cache_reloads_uncertain_commits_and_revokes_grants` unit test
covers both applied and unapplied errors and counts backing reads.
