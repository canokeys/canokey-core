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

## Protocol profile

Commands implemented: SELECT, SELECT DATA, GET DATA/NEXT DATA, VERIFY/logout,
CHANGE REFERENCE DATA, RESET RETRY COUNTER, INTERNAL AUTHENTICATE, PSO signature/
decipher, PUT DATA, IMPORT KEY, GENERATE/READ PUBLIC KEY, TERMINATE, ACTIVATE,
GET CHALLENGE, and CanoKey retry-limit command F2. ADMIN 03 resets OpenPGP after
ADMIN authentication; the ADMIN factory-reset workflow also resets OpenPGP.

Supported algorithms remain RSA-2048/3072/4096, P-256, secp256k1, P-384, P-521,
Ed25519 and X25519. X25519 is decrypt-role only; Ed25519 is sign/auth-role only.
RSA signatures use PKCS#1 v1.5 and RSA decipher validates v1.5 padding. Short
Weierstrass digests are left-zero-padded to the native scalar width without
changing their numeric value. Signatures are raw r||s; ECDH consumes the nested
A6/7F49/86 object. X25519 wire scalars are converted to the native representation
at import; public values and shared secrets retain their wire byte order.

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

## Streaming and memory

CCID retains its 261-byte short-frame limit. Logical commands span ISO chained
APDUs; general extended APDU support is not advertised. Request modes are:

- Small commands and irreducible RSA ciphertext: at most 513 bytes in the shared
  session input, rather than a separate worst-case buffer in each applet.
- Certificates: up to 1152 bytes, appended to a dedicated object transaction
  after PW3 authorization. Atomic rename publishes only the final complete
  object; abort/reset leaves the previous certificate authoritative. Reads use
  storage ranges and GET RESPONSE, without a certificate-sized RAM allocation.
- Key import: at most 1400 encoded bytes; only a 48-byte structural prefix is
  collected. Descriptor lengths route each component directly into the shared
  key representation, across arbitrary frame boundaries. No whole encoded-key
  buffer or unauthenticated generic flash RX scratch exists. Final validation
  and publication happen once, after the complete envelope is consumed.

Workspace size is 2332 bytes including alignment: one 1288-byte `KeyMaterial`,
513-byte crypto input and 528-byte semantic output plus small framing. RSA's
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
ECC stores only its private scalar. A new signing key and its zero
counter publish in one transaction. Successful signing persists its increment
before exposing the response; delivery failure does not roll the counter back.
The 24-bit counter saturates rather than wrapping to zero.

Multi-record reset first marks the applet terminated and clears that marker last;
an interrupted reset remains recoverable with ACTIVATE. Storage failures are
fail-closed (`6900`), never a trigger to format or reinterpret old C records.
`s` is separate from `t` used for atomic record updates.

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
