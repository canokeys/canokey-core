# Rust CTAP migration

The independent `ctap` feature links no C CTAP dispatcher or applet. It is a
**development profile**, not a complete authenticator. It currently supports:

- CTAPHID INIT, PING, WINK, LOCK and CBOR dispatch; INIT advertises WINK and
  CBOR (`0x05`). NMSG is not advertised. U2F/MSG handling is available through
  the native transport path.
- CCID FIDO SELECT (`00 A4 04 00`, AID `A0000006472F0001`) returns `FIDO_2_0`.
  `80 10 00 00` carries CTAP bytes; ISO chaining uses CLA `90` and final CLA `80`.
  GetInfo is command `04`, with no parameters. Unknown CTAP commands return
  CTAP INVALID_COMMAND inside a successful APDU envelope.
- clientPIN (`06`) protocols 1 and 2: getPinRetries, getKeyAgreement, setPIN,
  changePIN, legacy getPinToken and getPinUvAuthTokenUsingPinWithPermissions.
  GetInfo reports the actual configured-PIN flag and protocols `[1, 2]`.
- GetInfo is encoded once with minicbor into the shared response workspace.
  It reports resident credentials, ES256/Ed25519/SM2, credential management,
  largeBlobs and the implemented extensions. The zero AAGUID identifies this
  unprovisioned development profile.
- authenticatorSelection (`0b`) waits up to 30 seconds for a fresh press/release.
- authenticatorConfig (`0d`) supports toggleAlwaysUv (2), setMinPINLength (3),
  and enableLongTouchForReset (4). GetInfo reports these capabilities and policy.
- authenticatorReset (`07`) is admitted only within ten seconds of power-on and
  requires a fresh gesture before deleting PIN/policy, master, counter, resident credentials and largeBlob records. With long-touch
  reset enabled, short gestures are ignored; a fresh hold of at least 500 ms and
  release is required, matching the CIU C touch classifier.
  Transport resets cannot restart the power-on window. A failed deletion revokes
  cached authorization but does not restore retry counters. Future CTAP records
  must join this reset path when their owning commands are added.

- makeCredential/getAssertion/getNextAssertion support ES256, Ed25519, ML-DSA-65 and default-profile SM2 with
  independently verified packed self-attestation and assertion signatures.
  U2F registration continues to require the provisioned attestation key and
  certificate because its wire format has no packed self-attestation variant.
  ML-DSA makeCredential also requires provisioned P-256 attestation material;
  its 3309-byte signature cannot fit the bounded packed framing workspace.
  Discoverable credentials, exclusion, credProtect, minPinLength (RP allowlist),
  credBlob (32 bytes), largeBlobKey, hmac-secret/hmac-secret-mc (protocols 1/2),
  and thirdPartyPayment are implemented.
- Credential management (`0a`, preview `41`) supports metadata, RP/credential
  enumeration, deletion and user-information updates with CM token permission.
- largeBlobs (`0c`) supports a 4096-byte serialized array and 960-byte fragments.

Configurable SM2 COSE identifiers remain to be migrated. CANCEL is silent when
idle or receiving; while a command waits, same-channel CANCEL returns CTAP `2d`.
The independent CTAP firmware is the implementation target; combined firmware
capacity is deferred until protocol functionality is complete.

## Credentials and large blobs

Record `4e` holds a 32-byte random master; `4f` holds the four-byte big-endian
signature counter. A 34-byte credential ID contains algorithm, policy flags,
16-byte nonce and 16-byte authentication tag. HMAC domains separate handle tags,
private keys and largeBlob keys; all bind the RP hash. Nonresident credentials
use no per-credential Flash. Counters commit before signatures are published.

Records `50`..`b3` hold up to 100 discoverable credentials. Each contains the ID,
RP hash and length-prefixed RP display prefix, user ID, name, display name and
credBlob. Empty fields cost one byte; no padding, version prefix or auxiliary
index is stored. Re-registering the same RP/user replaces one atomic record,
invalidating the old resident ID. Enumeration scans these records and keeps only
small cursors in RAM. getNextAssertion expires after 30 seconds or another command.

For makeCredential, a credBlob longer than 32 bytes is consumed within the
normal request-size limit and reported as `credBlob: false`; the credential
still succeeds, and no truncated blob is persisted. getAssertion then returns
an empty blob. Nonresident credentials also report `false`. RP enumeration
groups duplicate RP hashes using its visited bitmap and reloads the selected
record after scanning with the shared buffer, so its RP ID and hash always
come from the same record.

Record `b4` holds the committed serialized large-blob array. Each set fragment is
materialized in the shared command workspace, releasing input PKE before crypto.
PIN-protected writes require LBW permission and authenticate exactly
`FF*32 || 0c00 || LE32(offset) || SHA256(fragment)`. Only authenticated fragments
enter a durable upload transaction. SHA-256 is accumulated in RAM; the checksum
must match before atomic publication. Failed/interrupted uploads preserve the old
array. Reads stream directly from the committed file into response fragments;
no whole-blob RAM buffer or Flash request cache is used.

The host end-to-end test uses production Rust and C crypto adapters with
python-fido2 for independent CBOR, PIN protocol and signature verification:

```sh
cmake -S canokey-core/rust -B build/rust-ctap-host -DCANOKEY_APPLET_CTAP=ON \
  -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE="$PWD/.venv-hil/bin/python"
cmake --build build/rust-ctap-host -j8
ctest --test-dir build/rust-ctap-host --output-on-failure
```

The selected Python needs `fido2`, `cryptography`, `jsonschema` and `jinja2` (the
last two also serve the crypto dependency's code generator). Host success does
not establish device stack high-water or timing; use the independent DevKit
profile and boot gate for target validation.

## SM2 credential profile

The default C profile uses COSE algorithm -54 and curve 9. Rust supports the
same identifiers for registration, assertions and credential management; custom
identifiers through ADMIN are not yet migrated. SM2 stores the same compact
34-byte credential ID as the other algorithms. Private-scalar derivation rejects
zero and scalars at or above n-1 (SM2 signing needs the inverse of 1+d), retrying
with a fresh nonce without modular reduction.

SM2 signs `SM3(ZA || authData || clientDataHash)` with the standard identity
`1234567812345678`. Signatures are the 64 raw big-endian bytes r||s, matching C;
only ES256 signatures use DER. A small key-service digest operation computes ZA
and SM3 using existing primitives. It keeps the SM3 context in a separate frame
from ordinary ECC signing. The host test uses the independent Python SM2 group
and SM3 implementation for self-attestation and assertion verification, including
resident enumeration, RP/algorithm-tamper rejection and restart persistence.

## Secret extensions and credential responses

hmac-secret and hmac-secret-mc reuse clientPIN's P-256 decapsulation and protocol
1/2 key derivation. The streaming schema owns only the peer point, encrypted
salts and authentication tag; no request/PKE bytes remain live during crypto.
The MC variant requires `hmac-secret: true`; absent or false returns
MISSING_PARAMETER (14). Unsupported unsigned enterpriseAttestation values return
INVALID_PARAMETER (02), while other CBOR types return UNEXPECTED_TYPE (11).
Assertions with hmac-secret require
user presence. Invalid salt authentication never decrypts the salt.

CredRandom derives from the credential master with separate domains for UV and
non-UV operations, distinct from signing keys and largeBlobKey. Output uses
HMAC-SHA-256 for each salt and AES-256-CBC, with a fresh IV for protocol 2.
Only the prepared salts and AES key survive getNextAssertion. They are wiped at
enumeration completion, error, reset or any unrelated command. No extension
secret is cached in Flash. thirdPartyPayment uses one authenticated credential
flag, including nonresident credentials, and is reported by assertions on request
and by credential management.

After signing, credential responses stream three segments: CBOR prefix, signed
authData, and CBOR suffix. Prefix/suffix share the existing 528-byte output area;
authData remains in the existing input area. This supports full user metadata
and simultaneous extensions without increasing either buffer. The key workspace
is still wiped immediately; retained response bytes are public protocol output.

## PIN state

Record `4d` atomically contains the PIN and policy in 20 + 32*N bytes:

- Bytes 0..15: SHA-256 PIN prefix; byte 16: retries; byte 17: Unicode code-point count (zero means no PIN).
- Byte 18: minimum PIN length; byte 19: alwaysUV / forceChange / longReset in bits 0..2, RP count N in bits 3..5.
- N RP ID SHA-256 hashes (N = 0..4), for the minPinLength extension allowlist.

Missing means unconfigured with eight retries and minimum four; malformed or
unreadable records fail closed. There is no format prefix, transport file or
Flash cache. This replaces the development 18-byte record: provision fresh
storage; no data migration is provided. PINs contain up to 63 code points and
63 UTF-8 bytes, without embedded NUL. Minimum length can only increase.

A bare `0d` command (no CBOR body) returns legacy status `F1`; a truncated
CBOR body returns `12`, while an empty map returns missing-parameter `14`.
These rejected requests do not mutate authenticator policy.

Config authentication covers `FF*32 || 0d || subcommand || subCommandParams`,
including the exact optional parameter-map encoding and unknown parameters.
When PIN or alwaysUV is set it requires a valid protocol 1/2 token with ACFG
permission (0x20); the exception is disabling alwaysUV when no PIN is set.
Setting forceChange without a PIN fails. Raising the minimum above the current
PIN length sets forceChange and revokes the token. Both token-issuance commands
are blocked until a valid changePIN atomically updates the PIN and clears the
flag (legacy returns PIN_INVALID; scoped issuance returns PIN_POLICY_VIOLATION).
The RP list replaces the previous list, including an empty list to clear it.
Only hashes are persisted; raw RP strings are not needed for extension matching.

ECDH uses the existing validated P-256 primitive. Protocol 1 derives SHA-256(Z);
protocol 2 uses the CTAP HKDF labels and separate HMAC/AES keys. Rust owns the
protocol schedule, with existing C hash/HMAC/AES/key primitives unchanged.
Encrypted fields, shared secrets, hashes and key workspace are wiped on exit.
PIN changes use atomic replacement. Wrong PIN attempts are charged durably before
comparison. Three consecutive failures require reboot; eight exhaust durable
retries. A transport/session reset clears key agreement and tokens but cannot
restore either retry counter. Valid PIN verification restores durable retries.
Invalid changePIN authentication never consumes a retry.

Key agreement and token state live in one shared CTAP session across HID commands;
APDU preemption clears that authorization session. Token permissions/RP binding
are retained in RAM, never in transport/PKE storage. Each command expires tokens after 30 seconds without successful authentication
or ten minutes from issuance, using wrapping tick differences. Ordinary queries
never refresh these deadlines. The shared authorization helper verifies MAC,
permission and any supplied RP binding, then refreshes only the idle timer.
Config does not impose an RP constraint, matching C's ACFG permission check.

## Ownership and streaming

`protocol::ctaphid` decodes/encodes only the 64-byte wire layout.
`runtime::ctaphid::Transport` owns CID, sequencing, message length, receive
deadline and response position. `interfaces/rust-core/ctaphid.c` owns endpoint
reports and the ISR/main-loop handoff. USB interrupts never call Rust or PKE.

There is one queued report. The main loop copies it to a 64-byte local before
rearming OUT and lending the copy to Rust. This lets CANCEL arrive during a
presence wait without modifying Rust's borrowed input. An interrupt arriving
during an empty poll remains queued for the next poll. The endpoint driver
retains another 64-byte RX report; none is an entire request. Short requests use a 192-byte inline buffer. Larger requests use
`pke_buffer_read/write`, with a public message limit of 1024 bytes. There are no
transport files, Flash caches, heap allocations or full-request RAM buffers.

Before request staging, the FFI adapter requires CCID to be idle. After CCID's
final IN completion, a session with no input chain permits immediate takeover
when its response is complete or the applet declares its source abandonable,
matching the legacy preemptable-APDU rule. An ordinary response continuation
retains the two-second lease. The HID session retains its own
two-second idle lease. Admission then lets the other transport reset the session
(including PIN grants and key agreement) and acquire PKE. A queued CCID
packet cannot block the HID owner's commands during that lease; otherwise it
would force a premature preemption between getKeyAgreement and clientPIN. CCID
slot discovery and power requests remain responsive during an idle HID lease,
without resetting core; only APDU execution waits. Active HID execution still
excludes all CCID handling until its borrowed core state has returned. While HID aggregates or responds, CCID dispatch and keyboard
core calls wait. CCID link interrupts still run. These actual entrypoint gates,
not the PKE owner flag alone, exclude crypto that could clobber PKE.

GetInfo consumes its command byte and releases request storage before preparing
the response. Parsers copy needed semantic fields and close the
request before crypto, presence waits or other PKE users. `largeBlobs.set` and
other authenticated raw CBOR spans need their own bounded copy/verification schedule.
Config streams the envelope and copies only subCommandParams into the shared
request workspace (bounded by the 1024-byte request limit). Parser events carry
consumed-byte offsets, so split headers and unknown parameters retain their exact
encoding without a second parser or re-encoding. RP spans refer to this owned
copy, never to PKE. The command is moved out before the workspace changes to its
crypto view; crypto, hashing and storage run only after request release.
A source must not become a persistent collection of offsets into PKE.

PING is a transport-only exception: it echoes the staged request in ascending
chunks, without invoking applets/crypto, while retaining exclusive ownership.
The source closes once, after final IN completion or on abort/reset/error.
Rust rejects source results above the 7609-byte HID framing limit with
ERR_INVALID_LEN before sending a report, closing the response exactly once.
This response limit is distinct from the advertised 1024-byte request limit. Each
outgoing report remains owned by C until USB completes it; host retries never
repeat source reads or execute an operation again.

Execution begins only after request storage closes. Transport-only C progress
callbacks send KEEPALIVE every 100 ms while Rust waits; status is UPNEEDED for
presence and PROCESSING otherwise. A separate 64-byte control report remains
endpoint-owned until IN completion and never aliases the final Rust response.
The callback handles same-channel CANCEL, foreign-channel busy replies and USB
reset without reentering Rust or using PKE. Same-channel INIT is left queued;
the interrupted response is discarded before normal Rust INIT processing.
The final response waits for any control IN completion; after a one-second stall,
its obsolete reply is discarded and the in-flight control bytes remain untouched.
Long, non-cooperative crypto calls still need their own progress integration before
credential signing is enabled. CCID waits retain the existing time-extension path.

Presence uses the common runtime gesture implementation. A predating press must
be released before a fresh press/release; successful, timed-out and cancelled
attempts all consume the gesture for PASS keyboard-output inhibition. Timeout is
CTAP `2f`; reset outside the power-on window is `30`. Neither command accepts a body.

Receive timeout is 800 ms since the last packet's **receipt** timestamp, using
wrapping subtraction. Process queued input before checking current time. A foreign
CID gets CHANNEL_BUSY without altering the current transaction; same-CID INIT
resynchronizes it. Wrong sequence, timeout, staging failure and USB reset release
the source. After a one-second IN stall, release the source/session but retain the
submitted report until actual completion/reset. CIU's `FlushEP` is a no-op and
must not be used as permission to overwrite endpoint-owned bytes.

## Code layout

- `applets/ctap/mod.rs`: shared CTAP request state, commands and execution.
- `applets/ctap/client_pin.rs`: incremental clientPIN/COSE schemas.
- `applets/ctap/pin.rs`: PIN crypto schedule, compact record and retry policy.
- `applets/ctap/config.rs`: streamed config schema, token authorization and atomic policy updates.
- `applets/ctap/apdu.rs`: FIDO SELECT, APDU admission and response backing.
- `runtime/ctaphid.rs`: HID channel/fragments and request/response lifetime.
  Initialization, packet receive, completed-request execution and transmit are
  separate operations. One storage state tracks released, inline or PKE input.
- `runtime/ccid.rs` and `ffi/ccid.rs`: CCID framing and endpoint handoff; both queued
  late packets and clock expiry use the same receive cleanup.
- `protocol/cbor.rs`: bounded incremental adaptation of minicbor.

## Request parsing and CBOR

HID and APDU use `ctap::Request` to consume fragments and produce an owned
`Command` or CTAP error. `Session::execute` runs only after request storage closes.
APDU and HID semantic parsing occupy alternative views of the shared session
workspace (including HID MSG parsing); they
never add an applet-sized request buffer. Response cleanup preserves key agreement,
while session reset wipes authorization. HID reuses its 192-byte inline area as
its PKE read window. Prepared response reads never repeat crypto or encoding.

minicbor 2.3.0 is an unmodified upstream Git submodule at `minicbor/`, pinned to
`67b22f849a0ff12b669a0c304236ffe9744f9a79` (the release's recorded source commit).
Initialize it with `git submodule update --init --recursive`. Cargo uses the
`minicbor/minicbor` package as a path dependency with default features disabled.
The upstream BlueOak-1.0.0 license remains in the submodule.

String lengths use the same CBOR argument encoding as unsigned integers. The
adapter normalizes only their major-type bits in its bounded header buffer and
uses upstream `Decoder::u64` to decode the length. It then streams the body and
validates UTF-8 separately. No local minicbor patch or fork is required.

The adapter buffers at most a nine-byte header, container counters, and one
incomplete UTF-8 code point. minicbor interprets scalars and length headers;
`core::str::from_utf8` validates text. The adapter preserves push input across USB
and ISO APDU fragments. It enforces shortest arguments, definite lengths, a byte
budget, depth eight and exactly one complete value. Tags/floats, invalid UTF-8,
truncation and trailing values fail. Consumer failure is terminal; provisional
events never authorize or write storage.

The clientPIN/config roots, recognized COSE maps and config parameter maps
require canonical integer-key order and unique keys. Unknown values are structurally skipped without retaining source
offsets. **Canonical key order in skipped unknown nested maps remains unchecked**;
complete CTAP validation must close that gap. Known fields have protocol-specific
length/type checks. Missing parameters return 0x14, wrong types 0x11, malformed CBOR
0x12, invalid protocol 0x02 and unsupported subcommands 0x3e.

## Standalone extended FIDO over CCID

After FIDO SELECT, CCID accepts `80 10 00 00 00 LcHi LcLo`, followed by
1..1024 CTAP bytes and optionally a two-byte Le. Lc and Le are big-endian.
This exception cannot start or finish an ISO command chain; other applets keep
short APDUs and chaining. The envelope itself requires no PIN; the embedded command decides authorization
and persistent side effects.

The short APDU buffer remains 261 bytes. Larger requests keep the seven-byte
prefix and optional Le in that buffer and stage only the body in PKE. Rust
validates the selected applet, command shape, size and session before PKE is
acquired, closing previous input/response resources first. A virtual input
source joins prefix, body and Le for the existing APDU parser. It closes before
applet finalization, including on read or parse failure.

The CCID ISR queues the endpoint buffer pointer and receipt timestamp. OUT stays
NAKed until the main loop consumes the packet; interrupts never call Rust or PKE.
Header fragments are supported. A two-second receive deadline rejects late
fragments, and errors/reset release staged input. USB connection generations
suppress replies from work interrupted by reset. Keyboard work waits while CCID
owns PKE, and HID waits until CCID is idle.

## Endianness and USB composition

USB SETUP fields and descriptor multibyte fields are little-endian. The USB core
already converts SETUP to native integers: class routing compares `wIndex` and
`wValue` directly, including on CIU BE8. CCID `dwLength` is also little-endian.
CTAPHID CID and BCNT, APDU extended lengths/status words, and CBOR integers are
big-endian on the wire. CID allocation is monotonic within the current boot;
channels are transport labels, not authentication capabilities.

When enabled, HID is interface 0, CCID is interface 1, and optional keyboard is
interface 2. Without CTAP, the existing CCID/keyboard interface numbers stay
unchanged. CTAP enables CCID extended exchange level and a 1043-byte maximum
message (10-byte CCID header + 7-byte APDU prefix + 1024-byte body + 2-byte Le).
Other profiles retain short exchange level and 271 bytes. Short HID transfers are discarded rather than parsing a stale tail.

## Validation

From the core directory:

```sh
cargo +nightly-2026-09-04 test --manifest-path rust/Cargo.toml --workspace --all-features
cmake -S rust -B build/rust-host
cmake --build build/rust-host --target hid-usb ccid-usb
ctest --test-dir build/rust-host -R '(hid|ccid)-usb' --output-on-failure
```

Config tests cover protocol 1/2 MAC message framing across all request splits,
permission and expiry rejection, compact RP hashes, monotonic minimum policy,
forceChange/token revocation, policy-preserving PIN changes, atomic-write failure
and long-reset gestures. Crypto is mocked in these policy tests; the existing
PIN HIL script independently verifies the primitives via python-fido2.

Rust tests cover literal endian vectors, request boundaries, monotonic source
reads, close-once semantics, contention, sequence/timeout/resync and injected
scratch failures. The C adapter test injects an interrupt during an empty poll,
checks pending IN-buffer retention after timeout, and resets during a Rust poll.
The CCID adapter test covers split headers, literal LE/BE lengths, PKE source
boundaries, cleanup, late packets, reset races and HID contention. Execution checks cover CANCEL during in-flight
KEEPALIVE, foreign-channel isolation, INIT resync and a stalled control endpoint. CBOR tests use
minicbor-generated vectors at every split, one-byte fragments, all truncated
prefixes, malformed canonical encodings, nesting limits and split UTF-8.

In the CIU parent repository:

```sh
cmake --preset devkit-rust-ctap
cmake --build --preset build-devkit-rust-ctap
.venv-hil/bin/python tools/hil/devkit_ctl.py --list
# Flash using the parent AGENTS.md workflow, then:
.venv-hil/bin/python tools/hil/rust_ctap_smoke.py --control <control-port> --output <report.json>
```

The read-only HIL checks run 70 PINGs at 0/57/58/192/193/256/1024 bytes, independently
decode GetInfo with python-fido2, check transport errors and CCID ownership, and
check extended CCID buffer/PKE boundaries through 1024 bytes, asymmetric Lc/Le,
malformed envelopes and chain conflicts, and optionally reset during a PKE-backed
request. They create no credentials or PINs.

## Remaining migration and target evidence

Continue with configurable SM2 identifiers and provisioned attestation. Long crypto needs cooperative
progress/cancellation. Nested unknown CBOR maps and long unknown text keys still
need canonical-validation review. Preserve the input-close boundary throughout.

The independent CTAP Release build on 2026-09-24 uses 104,192 Flash bytes and
6,732 static RAM bytes and passes the 48-vector/early-ResumeLoader gate. Other
Rust applets are disabled in this profile. Combined capacity is deliberately
deferred; do not change FS_BASE or crypto performance to make the combined image
fit during functional migration. Normal C DevKit and NFCC builds also pass.

The 171-check host flow independently verifies ES256/Ed25519/SM2 signatures,
resident replacement/persistence, both PIN protocols, permission and RP binding,
credential management, credProtect/minPinLength/credBlob/largeBlobKey, and
largeBlob fragmentation, LE offsets, integrity rejection and interrupted uploads.
It also checks hmac-secret registration/assertion consistency, single/double salts,
protocol interoperability, UV domain isolation, invalid MAC/peer rejection,
getNextAssertion and maximal responses exceeding 528 bytes.
CTAP CTest passes 5/5, and the existing combined host suite passes 9/9.

The saved DevKit clientPIN workload paints 3,464 of the 5,120-byte ordinary stack
budget, with 7,680 bytes reserved. This is an older PIN-only measurement, not
validation of the new credential, management or largeBlob call paths. The new
image has been built but has not yet been flashed or measured on device.

Dedicated-device PIN validation (leaves PIN `12345678` configured, after temporary
changes; requires that PIN if already configured):

```sh
.venv-hil/bin/python tools/hil/rust_ctap_pin.py --output /tmp/rust-ctap-pin.json
```

The script uses python-fido2/cryptography independently for ECDH, KDF, AES-CBC,
HMAC and token decryption under both protocols. Run the read-only transport smoke
before/after it. Preserve evidence of firmware identity and stack profile settings.

Implicit APDU routing after a slot reset is supported for CLA 80/90 INS 10
(CTAP2), CLA 00 INS 01/02/03 (U2F), and CLA 00 INS A4 with P1 other than 04.
ISO SELECT-by-name retains precedence, including invalid-P2 rejection. Routing
only applies while no applet is selected and still checks the persistent
WebAuthn permission before consuming/executing a request. An already selected
ADMIN, OpenPGP, PIV, OATH or NDEF applet is never replaced by this heuristic.
Extended CCID/NFC admission can recognize an implicit FIDO header without
mutating selection; normal command start performs the permission check. The
streaming regression exercises a source-backed CBOR request without SELECT,
including bounded length, owner restrictions, source cleanup and chain errors.


### Full host HID execution regression

Host CMake builds `hid-core` whenever `CANOKEY_APPLET_CTAP=ON`. It links a separate
Rust archive with `usb-hid`, the production HID mailbox/link/framing code and the
CTAP applet, plus native host crypto. Packet hardware, monotonic time, physical
presence and PKE scratch are simulated; record storage is volatile. APDU-only
fixtures retain their fail-on-use HID stubs and do not substitute for this test.

Run `ctest --test-dir <host-build> -R '^hid-core$' --output-on-failure`. Coverage
includes long echo, source-backed clientPIN crypto, GetInfo streaming, sequence
errors/timeouts with scratch cleanup, execution busy/keepalive/cancel, same-CID
INIT and disconnect response suppression. This is not USB controller, durable
storage or physical interoperability acceptance. The [Rust UDP virtual card](../host/README.md) uses these same production
entrypoints with durable host records and runtime error injection. PC/SC and AFL
remain separate legacy consumers.


### NFCCTAP_MSG polling hint

`80 10 00 00` and `80 10 80 00` both accept CBOR commands. P1 bit 7 is the
NFCCTAP_GETRESPONSE polling hint used by python-fido2; the synchronous engine
finishes directly with a response and `9000`, as the prior C engine did. It does
not promise an asynchronous `9100` response or invent a second command/session
workspace. Other P1 bits and nonzero P2 remain rejected with `6A86`. This admission
is shared by short/chained APDUs, standalone extended CTAP input and HID MSG.
The PC/SC daemon/client regression uses the client's default P1=80; disabling
that flag on the client would hide a firmware compatibility failure.

### CCID presence polls during HID execution

The cooperative HID progress path services complete, bodyless CCID
`PC_to_RDR_GetSlotStatus` requests without borrowing Core or shared scratch.
Replies preserve the CCID slot state and sequence and retain their endpoint
buffer until IN completion. Power/reset, APDU, fragmented and body-bearing
requests remain queued for the main loop. A USB generation change never triggers
Core reset from this callback. The `usb-sessions` fixture exercises two polls,
IN backpressure, deferred power-on and cancellation inside a real HID selection
presence wait.

### ML-DSA response streaming correctness

ML-DSA makeCredential uses the same extension encoder as classic credentials,
preserves UP/UV/ED flags and one counter increment, and splices the public bytes
after the COSE header and before extensions. The P-256 attestation hash covers
that exact authenticatorData; its DER signature is inserted once. Assertion
framing includes CTAP status, credential descriptor, resident user data and
largeBlobKey, and accounts for authenticatorData when moving into the shared
stream workspace.

Credential management encodes directly from the shared resident input record,
including maximum user fields, before reusing that input for its ML-DSA seed.
The seed remains owned until Stream::transfer copies it and clears the old
workspace. Full enumeration returns the registration public key; metadata-only
mode omits it. No second full public-key buffer or Flash scratch is introduced.
`ctap-normal` independently verifies packed attestation and ML-DSA signatures,
decrypts hmac-secret-mc results and compares full/metadata mixed enumeration.
Hardware stack measurements remain required for the repaired call paths.

Applet deselection clears both resident assertion and credential-management
continuations as well as volatile PIN authorization and key agreement. The
`ctap-normal` APDU fixture verifies this through SELECT ADMIN / SELECT FIDO,
then confirms management works after fresh clientPIN authorization.

GetInfo advertises `pinUvAuthToken: true` for permission-scoped clientPIN
subcommands, alongside PIN protocols 1 and 2. This option lets clients select
the supported permission-scoped authorization flow rather than legacy tokens.
