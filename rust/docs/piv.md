<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent Rust PIV

The `piv` feature implements the commands and algorithms in the C PIV applet
(`applets/piv/piv.c`, `piv-attestation.c`, and `include/piv.h`). Rust owns command
parsing, authorization, object/key storage, policy, and certificate encoding.
`interfaces/rust-core/key_crypto.c` and `piv_crypto.c` expose cryptographic
primitives only; the independent firmware does not link C applets or their
dispatcher. NFCC support remains deferred for all independent Rust profiles.

## Command coverage

| Command | Shape / authorization / effects |
|---|---|
| SELECT | Full 11-byte AID, nine-byte right-truncated AID, or legacy five-byte RID; other prefix lengths are rejected; repeated selection preserves PIN/PUK and management authorization, abandons transient streams and challenges. |
| VERIFY / logout | `20 00 80` with eight bytes verifies PIN; empty queries status. `20 FF 80` revokes PIN authorization. |
| CHANGE REFERENCE DATA | `24 00 80/81`, old and new eight-byte PIN/PUK. |
| RESET RETRY COUNTER | `2C 00 80`, eight-byte PUK and new PIN; does not grant PIN authorization. |
| GET CHALLENGE / version / serial | `84`, `FD`, `F8`, zero P1/P2. Versions come from the same CMake release fields as C. |
| GET / PUT DATA | `CB/DB 3F FF`, `5C <tag>`; PUT requires management authorization. PIN protects biometric and printed objects. |
| GENERAL AUTHENTICATE | `87 <algorithm> <slot>`, `7C` template; key-specific PIN and touch policies. AES-192 external and mutual management authentication use slot 9B, P1=00/0A. |
| GENERATE | `47 00 <slot>`, `AC {80 <algorithm>, [AA <PIN policy>], [AB <touch policy>]}`; management authorization. |
| IMPORT | `FE <algorithm> <slot>`, incremental native PIV component TLVs and optional AA/AB policies; management authorization. |
| Management-key rotation | `FF FF FF/FE`, `0A 9B 18 <24 bytes>`; management authorization, FE enables mandatory touch. |
| Metadata / directory | `F7 00 <reference>` or `F7 01 00`; public keys, policies, origin, default-credential and retry information. |
| Container name | `F5 00/01 <slot>` reads/writes up to 78 bytes of valid UTF-16LE; writes require management authorization and nonempty names must be unique. |
| Move / delete | `F6 <destination/FF> <source>`; management authorization, ordinary slots only, certificates stay in place. |
| Retry limits | `FA <PIN limit> <PUK limit>`, empty body; both management and PIN authorization, limits 1..15, resets credentials and revokes grants. |
| Factory reset | `FB 00 00`, empty body; requires both PIN and PUK blocked. Preserves F9 key/certificate and algorithm mapping. |
| ADMIN PIV reset | In ADMIN, `04 00 00`, empty body, verified ADMIN PIN; revokes PIV session grants and resets PIV credentials/ordinary keys/objects. Preserves F9 and algorithm mapping. |
| Algorithm mapping | `EE 01/02 00` reads/writes the C ten-byte configuration; writes require management authorization. |
| Attestation | `F9 <slot> 00`, empty body; generated keys only, no authentication, P-256 F9 signer and provisioned F9 certificate required. |

Ordinary asymmetric slots are 9A/9C/9D/9E and 82..95; F9 accepts P-256 and
remains signing-only. PIN policies are never/once/always (1/2/3); defaults are
always for 9C, never for 9E/F9, once elsewhere. Touch policies are never/always/
cached (1/2/3), with the C 15-second cache. A request owns its gesture so PASS
cannot reuse a touch consumed by PIV.

RSA IMPORT rejects zero-length or oversized integer components with `6A80`,
matching the native parser. Truncated AA/AB policy fields in IMPORT or GENERATE
return `6700`. Failed requests preserve the previous key and policies;
`piv-normal` checks metadata preservation and independently verifies a subsequent
private operation with the original key.

Mutual management authentication accepts the optional empty `82 00` response
placeholder alongside the witness and host challenge, as in the native applet.
AES-192 uses algorithm ID `0A`; `08` is not an AES-192 alias.

## Algorithms and streaming

RSA-2048/3072/4096 support key generation, validated CRT import, public export,
and raw private operations. P-256, secp256k1, P-384 and P-521 support generation,
scalar import, DER ECDSA signatures and ECDH. ECDSA digest integers are
left-padded to curve width, including C's P-521 leading-byte convention.
Ed25519 supports deterministic messages up to 544 bytes and randomized
long-message signing with P1=FF. X25519 supports agreement with the same
wire/native endian conversion as C.

SM2 supports 32-byte digest signing, chained full-message signing of
`SM3(Z || message)`, and GM/T 0003.2 key agreement. A chained first GA selects
message signing: `7C {[80 <own ID>], 82 00, 81 <message>}`. IDs are 1..32
bytes, defaulting to `1234567812345678`; signatures are raw 64-byte r||s.
Non-chained key agreement accepts:

- Initiator step 1: `7C {[80 <own ID>], 82 00}`; returns tag 82 with ephemeral point.
- Initiator step 2: `7C {82 00, 85 <peer template>}` on the same slot; returns tag 82 with shared key.
- Responder: `7C {[80 <own ID>], 82 00, 85 <peer template>}`; returns ephemeral point in 82 and shared key in 85.

The peer template is ordered `86 <04||static>, 87 <04||ephemeral>, [88 <ID>],
[89 <two-byte key length>]`; key length defaults to 16, range 1..128.
Plain ECDH is rejected for SM2. Initiator ephemeral material lives in the shared
workspace, is checked against its public key and current slot key before use,
and is cleared on failure, non-GA commands, selection and reset.

ML-DSA-65 persists a 32-byte seed (import tag 09), streams its 1952-byte public
key and 3309-byte signature, and hashes messages incrementally. ML-KEM-768
persists only 64-byte d||z (import tag 0A), derives its 1184-byte public key,
and decapsulates 1088-byte ciphertexts into 32-byte shared secrets with implicit
rejection. Neither expanded private keys nor complete long messages are stored.
PQ GENERATE stages only the compact metadata/seed record. The previous slot and
name remain intact until the final public-response chunk has been generated;
that chunk commits the replacement before returning success. Selection, reset,
rejected commands and session cleanup abort an unfinished replacement. Commit
failure returns an error and preserves the previous record. The seed crosses
the classic-to-stream workspace transition in a wiped 64-byte local; no extra
persistent scratch buffer or public-key Flash cache is allocated.
Short command chaining and GET RESPONSE are supported; extended APDUs are
rejected, matching C. Only GA, PUT and IMPORT accept command chaining.

Attestation generates DER X.509 with the F9 certificate's subject as issuer and
its validity period, random serial, CanoKey subject, device serial and policy
extensions. Serial numbers use minimal positive DER INTEGER encoding, including
leading-zero removal and sign padding; the unit suite covers these boundaries.
It covers RSA, all supported EC/Ed/X curves and ML-DSA. Like C,
ML-KEM attestation is rejected. The response is an 18-segment plan with at most
256 encoded bytes; issuer/validity are read from storage, and the ML-DSA public
key is regenerated for the hashing and response passes.

## Storage and lifecycle design

ADMIN, OpenPGP and PIV use the [shared PIN mechanism](pin-mechanism.md).
Applet adapters retain retry-charging and authorization semantics. PIV's
21-byte PIN/PUK record contains a version, two retry counters, two retry limits,
and two eight-byte credentials. Authorization is never persisted.
Failed credential writes invalidate the cache and revoke both grants; reset
alone cannot make an uncertain cache authoritative.

PIV records use hexadecimal filenames `0e`..`4c`, with no directory prefix.
Keys store six metadata bytes, private material and the actual name bytes.
RSA material is exponent4 plus five active-width components (644/964/1284
bytes); ECC and PQ records store only their scalar or seed. No padding or
previous-format decoder is persisted. Provision fresh storage.
Object capacities match C: certificates 6568 bytes, other large objects 3040,
admin data 128. Empty `53 00` certificate writes delete the object. PUT and key
replacement use staging plus atomic rename; interrupted writes keep the previous
committed record. Provisioning uses a completion marker and can resume an
interrupted explicit reset. Initial provisioning preserves the initialized
PIN/PUK record; a missing marker with established key/object storage fails closed.
F9 is excluded from reset deletion. In combined profiles, ADMIN factory recovery
(`50 00 00`, body `RESET`, blocked ADMIN PIN and five confirmation gestures)
also resets PIV. ADMIN PIN is restored last so an interrupted recovery remains
locked and retryable.

`protocol.rs` owns command dispatch and session state. Its child modules handle
management authentication, keys, metadata, staged objects, provisioning and
streaming. All private-operation paths use one PIN-consumption rule. Parser and
stream phases have named variants; persistent metadata uses named, stable byte
offsets. Crypto operations have explicit ABI discriminants in Rust and matching
C constants in `interfaces/rust-core/crypto_ops.h`.

A single registry-owned `SessionWorkspace` has mutually exclusive classic,
streaming-crypto and attestation views; OpenPGP uses the classic view. No applet
has a second worst-case crypto buffer. Native stream resources are aborted before
switching views; GET RESPONSE must not cancel its own live source. Cleanup runs
on response completion, abandonment, parser errors, session reset and transport
preemption. Explicit non-inlining keeps attestation and classic dispatch frames
out of PQ call paths. Scalar-backed plan storage allows in-place initialization
on Thumb-1 without multi-kilobyte aggregate copies.

Intentional improvements over C are atomic object replacement and deriving the
PIN-default metadata flag from the actual credential (including PUK reset).
Malformed duplicate GA tags and invalid DER are rejected; exact error precedence
for every malformed legacy input is not an interoperability guarantee. Rust
storage is not a migration/import of legacy C credential files.

## Validation

From the parent CIU repository:

```sh
cmake -S canokey-core/rust -B build/rust-piv-host -DCANOKEY_APPLET_PIV=ON
cmake --build build/rust-piv-host
ctest --test-dir build/rust-piv-host --output-on-failure

cmake -S canokey-core/rust -B build/rust-combined-host \
  -DCANOKEY_APPLET_OPENPGP=ON -DCANOKEY_APPLET_PIV=ON
cmake --build build/rust-combined-host
ctest --test-dir build/rust-combined-host --output-on-failure

python3 tools/hil/test_rust_storage.py

cmake --preset devkit-rust-piv
cmake --build --preset build-devkit-rust-piv
```

The Python PIV suite requires `cryptography >= 50` for independent ML-DSA/ML-KEM
verification. It tests classical/PQ key generation and imports, signatures,
ECDH and SM2 agreement, implicit rejection, X.509 attestation, management auth,
objects, policies, retry/reset, all retired slots, interrupted input and
abandoned output. SM2 arithmetic is independently checked by `tests/piv_sm2.py`.
The native storage contract test compiles the production LittleFS backend with
a RAM block device, including path IDs, staged replacement, move/delete, remount
and failure invalidation. Host builds link the production `key_crypto.c` and `piv_crypto.c` adapters against
the host primitive backend; there is no second test implementation of those
adapters. Python independently verifies their outputs. `combined-reset` seeds
all applets, checks authorized/unauthorized ADMIN PIV reset, then verifies that
factory recovery clears every applet.

The Python suites share `card_test.py` for transport and APDU handling. PIV
scenarios are ordinary functions, reused by host and HIL. Reports count completed
logical command checks (including automatic chaining/GET RESPONSE), not independent
scenarios. On failure they retain completed steps, the failing APDU identifiers,
its duration, the active scenario and error. Rust tests cover retry durability, PIN error paths and transport cleanup.

DevKit builds require the 48-vector/early-ResumeLoader boot gate. Host tests,
linking, and offline stack inspection alone do not establish measured device stack
high-water, power-loss recovery, or third-party PIV client interoperability;
these require dedicated-device HIL validation. Rust NFCC is not enabled.

### CIU DevKit validation, 2026-09-23

The CIU port's `tools/hil/rust_piv_smoke.py` passed 280 checks on both the
ordinary PIV image and an optional stack-report image. Independent host checks
verified the classical, SM2 and PQ operations and attestation certificates.
`rust_piv_persistence.py` passed 41 checks across actual CIU reset and power
off/on, covering keys, a 6504-byte object, names, changed PIN/management key,
retry counts and cleared authorization. These are completed-write persistence
checks, not arbitrary power cuts during flash writes. Physical touch and
third-party PIV client interoperability were not exercised.

HIL exposed missing timer-based CCID time extensions in PIV-only builds;
the transport now enables the same timer for either PIV or OpenPGP. A successful
31-second generation on the instrumented image exercised the corrected path.
Separating buffered-command temporaries from private-operation dispatch reduced
the observed RSA-2048 path high-water from 5300 to 4956 bytes.

Isolated `rust_piv_stack.py` runs measured P-521 generation at 5016 bytes and
P-521 attestation at 6288 bytes, versus ML-DSA-65 generation at 3688 bytes and
attestation at 4672 bytes. These are complete APDU-path high-water measurements,
including protocol and interrupt frames. The 6288-byte peak is above the ordinary
5120-byte target, with 1392 bytes remaining in the 7680-byte reserved stack;
this run found no overflow, but does not establish the ordinary budget or a
worst-case bound for every interrupt schedule. The UART algorithm tag records
the last classic primitive, so peak attribution uses isolated requests instead.
Reports are in the CIU workspace's `hil-reports/rust-piv-20260923/` directory.

### Review refactor validation

The follow-up review fixes passed six combined host suites, including a new
cross-applet ADMIN reset regression, and isolated empty/ADMIN-PASS/OpenPGP/PIV
profiles. DevKit PIV passed the same 280 command checks and 41 reset/off-on
persistence checks after the refactor. P-521 generation/attestation painted
5024/6296 bytes (previously 5016/6288); ML-DSA remained 3688/4672. Static RAM
is unchanged. Full evidence is in the CIU port's
`hil-reports/rust-review-20260923/README.md`.
