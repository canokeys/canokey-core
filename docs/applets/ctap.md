# Rust CTAP migration

`ctap::Applet` owns shared session/execution/response state. The APDU adapter is
in `apdu.rs`; HID MSG framing and continuation are in `message.rs`. Native HID
and APDU commands use the same container and transient workspace. ADMIN reset
uses `reset_persistent`; ordinary transport/session reset does not erase records.
Provisioning and SM2 settings return typed errors mapped by ADMIN to its existing
status words. Certificate staging owns begin, append, commit and abort together.

## Resident storage groups (2026-10-01)

Fresh provisioning is required. There is no migration or compatibility decoder.
The 100 logical slots share 25 physical files, `50`..`68`, four consecutive slots
per file. Each begins with `CTG1`, four big-endian u16 lengths (zero means absent),
then present payloads in slot order. Payloads remain at most 327 bytes; the group
maximum is 1320 bytes. Invalid headers, lengths, truncation and trailing bytes
fail closed. Reads validate the envelope and requested member; mutations also
validate copied members before publication.

Mutations stream into the session stage using disjoint existing workspace
borrows and a single atomic publish. Last-member deletion removes the file.
No group-sized stack buffer or extra file cache is used. Enumeration and
same-RP/user replacement retain logical-slot order. Reset deletes groups and
user-information updates retain best-effort semantics: they return success even
if group publication fails or has an uncertain outcome. Credential deletion
propagates storage errors. Atomic group publication still prevents partial
records; it does not imply that a best-effort command reports storage failure.
Actual CIU-model fault
tests compare complete old/new group bytes. Capacity depends on occupancy and
field lengths; see the platform NFCC storage capacity report.

The independent `ctap` feature links no C CTAP dispatcher or applet. It is a
**development profile**, not a complete authenticator. It currently supports:

- CTAPHID INIT, PING, WINK, LOCK and CBOR dispatch; INIT advertises WINK and
  CBOR (`0x05`). NMSG is not advertised. U2F/MSG handling is available through
  the native transport path.
- USB CCID/WebUSB FIDO SELECT (`00 A4 04 00`, AID `F043414E4F464944`) returns the legacy six-byte `U2F_V2` response.
  NFC uses standard AID `A0000006472F0001`.
  CTAP2 GetInfo continues to advertise the supported FIDO2 versions; keeping
  SELECT at six bytes preserves existing U2F/NFC client buffers. Unknown U2F
  instructions return `6D00` for both short and well-formed extended APDUs;
  malformed framing and command-size limits still reject invalid lengths.
  `80 10 00 00` carries CTAP bytes; ISO chaining uses CLA `90` and final CLA `80`.
  GetInfo is command `04`, with no parameters. Unknown CTAP commands return
  CTAP UNHANDLED_REQUEST (`F1`) inside a successful APDU envelope.
- clientPIN (`06`) protocols 1 and 2: getPinRetries, getKeyAgreement, setPIN,
  changePIN, legacy getPinToken and getPinUvAuthTokenUsingPinWithPermissions.
  GetInfo reports the actual configured-PIN flag and protocols `[1, 2]`.
- GetInfo is encoded once with minicbor into the shared response workspace.
  It reports resident credentials, ES256/Ed25519/ML-DSA-65/ML-DSA-44/SM2, credential management,
  largeBlobs and the implemented extensions. The AAGUID is
  `244eb29e-e090-4e49-81fe-1f20f8d3b8f4`.
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

- makeCredential/getAssertion/getNextAssertion support ES256, Ed25519, both ML-DSA parameter sets and default-profile SM2 with
  independently verified packed self-attestation and assertion signatures.
  U2F registration continues to require the provisioned attestation key and
  certificate because its wire format has no packed self-attestation variant.
  ML-DSA makeCredential also requires provisioned P-256 attestation material;
  their3309/2420-byte signatures cannot fit the bounded packed framing workspace.
  Discoverable credentials, exclusion, credProtect, minPinLength (RP allowlist),
  credBlob (32 bytes), largeBlobKey, hmac-secret/hmac-secret-mc (protocols 1/2),
  and thirdPartyPayment are implemented.
- Credential management (`0a`, preview `41`) supports metadata, RP/credential
  enumeration, deletion and user-information updates with CM token permission.
- largeBlobs (`0c`) supports a 4096-byte serialized array and 1232-byte fragments.

Admin configures SM2 COSE identifiers, excluding reserved algorithm IDs.
Idle/late bounded CANCEL is silent. During fragmented RX, same-channel CANCEL
is an unexpected initial report and returns HID sequence error; a foreign
CANCEL returns busy without altering RX. While a command executes, matching
zero-length CANCEL uses the transport progress path and returns CTAP `2d`.

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
cmake -S canokey-core -B build/rust-ctap-host -DCANOKEY_PROFILE=ctap \
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
the shared `canokey_ctap::extensions::hmac_secret::output` engine: prepare the
IV, write each HMAC-SHA-256 result directly into the existing ciphertext body,
then AES-256-CBC encrypt that body in place. Protocol 1 uses the zero IV;
protocol 2 obtains a fresh IV before salt HMAC. Invalid salt/output lengths
invoke no primitives. The caller wipes the credential key on every exit and
all output on failure; native HMAC scratch cleanup remains in the crypto adapter.
The shared tests cover both protocols, one/two salts, every output capacity and
partial RNG/HMAC/CBC failures; product vectors independently verify ciphertext.
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

Standard command error teardown consumes `canokey_ctap::session::reset_on_error`.
Internal (`0x7f`) revokes the complete authorization session because a primitive
or persistent commit may have left uncertain state. Ordinary request, token
MAC/scope and presence rejections retain agreement and any token not already
expired or consumed. Error cursor/output cleanup is separate and mandatory;
transport generation invalidation still revokes authorization. Product-only
storage/integrity errors must map to Internal or revoke in their adapter.

Key agreement and token state live in one shared CTAP session across HID commands;
APDU preemption clears that authorization session. Token permissions/RP binding
are retained in RAM, never in transport/PKE storage. Each command expires tokens after 30 seconds without successful authentication
or ten minutes from issuance, using the shared `client_pin::token::lifetime_remaining`
engine over wrapping tick differences. The limits live in the shared CTAP crate;
products retain the clock origins and revocation/wipe owners. Ordinary queries
never refresh these deadlines. The shared authorization helper requires a
nonzero permission mask with every requested bit, checks any supplied RP binding,
then verifies the MAC once. Product ordering and partial-permission profiles are
not available. Only successful admission refreshes the idle timer; zero masks,
missing grants, RP mismatches and failed MACs do not refresh it. Primitive MAC
errors retain their native status. Shared and Core adapter tests cover combined
permission/RP/MAC failures, zero masks and unsuccessful-use state preservation.
Config does not impose an RP constraint, matching C's ACFG permission check.

## Ownership and streaming

`protocol::ctaphid` decodes/encodes only the 64-byte wire layout.
`runtime::ctaphid::Transport` owns CID, sequencing, message length, receive
deadline and response position. `crates/ffi/src/transport/hid/` owns endpoint reports and the ISR/main-loop
handoff. USB interrupts never enter the core or use PKE.

There is one queued report. The main loop copies it to a 64-byte local before
rearming OUT and lending the copy to Rust. This lets CANCEL arrive during a
presence wait without modifying Rust's borrowed input. An interrupt arriving
during an empty poll remains queued for the next poll. The endpoint driver
retains another 64-byte RX report; none is an entire request. Short requests use a 192-byte inline buffer. Larger requests use
`pke_buffer_read/write`, with a public message limit of 1296 bytes. There are no
transport files, Flash caches, heap allocations or full-request RAM buffers.

Before request staging, the FFI adapter requires CCID to be idle. Active
APDU input chains and ordinary pending responses retain their owner until
completion or an explicit lifecycle event; elapsed idle time does not release
them. Native HID execution borrows the shared workspace without revoking the
retained APDU selection or PIN grant. A completed, preemptable session may yield
to an actual competing command. Rejected admission, INIT/CANCEL traffic and
passive polling must not revoke another interface's grant.

Native MSG continuations retain explicit HID ownership across arbitrary idle
gaps. CCID slot discovery and power requests remain responsive as permitted by
execution/ownership state; slot power revokes APDU context. Active HID execution
still excludes general CCID dispatch until its borrowed Core state returns;
presence progress services only the permitted mailbox operations. USB IRQs never
borrow Core. These entrypoint gates, together with lease cleanup, protect PKE.

GetInfo consumes its command byte and releases request storage before preparing
the response. Parsers copy needed semantic fields and close the
request before crypto, presence waits or other PKE users. `largeBlobs.set` and
other authenticated raw CBOR spans need their own bounded copy/verification schedule.
Config streams the envelope into the shared request workspace (bounded by
the 1296-byte request limit) and authenticates only the exact subCommandParams
span. Parser events carry
consumed-byte offsets, so split headers and unknown parameters retain their exact
encoding without a second parser or re-encoding. RP spans refer to this owned
copy, never to PKE. The command is moved out before the workspace changes to its
crypto view; crypto, hashing and storage run only after request release.
A source must not become a persistent collection of offsets into PKE.

Generic CTAP file segments and native HID require exact record reads. ISO U2F
registration instead uses `Storage::read_some_at`: a short certificate read
returns the already copied registration prefix plus actual certificate bytes,
then resumes at that exact offset on GET RESPONSE. Signature bytes are copied
only after the complete certificate. Zero total progress or excessive counts
fail and close the response source; bytes outside the returned prefix are never
published. Exact-only Storage backends keep their existing failure semantics.

PING is a transport-only exception: it echoes the staged request in ascending
chunks, without invoking applets/crypto, while retaining exclusive ownership.
The source closes once, after final IN completion or on abort/reset/error.
Rust rejects source results above the 7609-byte HID framing limit with
ERR_INVALID_LEN before sending a report, closing the response exactly once.
This response limit is distinct from the advertised 1296-byte request limit. Each
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

Receive timeout occurs strictly after800 ms since the last packet's **receipt** timestamp, using
wrapping subtraction. Process queued input before checking current time. A foreign
CID gets CHANNEL_BUSY without altering the current transaction; same-CID INIT
resynchronizes it. Wrong sequence, timeout and staging failure release unfinished
input; pre-parser errors preserve an older native response continuation. Bind
that continuation to its producing CID, independently of the current request
CID. Other-channel CBOR, PING/WINK and malformed requests cannot transfer it;
foreign MSG returns busy without reading or advancing it. Bounded WINK payloads
are consumed and ignored. Reset/INIT close the continuation explicitly.
After a one-second IN stall, release the source/session but retain the
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
- `runtime/ccid.rs` and `ffi/transport/ccid`: CCID framing and endpoint handoff;
  accepted/refused RX drains its declared payload without a receive-gap deadline.
- `protocol/cbor.rs`: bounded incremental adaptation of minicbor.

## Request parsing and CBOR

HID and APDU use `ctap::Request` to consume fragments and produce an owned
`Command` or CTAP error. `Session::execute` runs only after request storage closes.
APDU and HID semantic parsing occupy alternative views of the shared session
workspace (including HID MSG parsing); they
never add an applet-sized request buffer. Response cleanup preserves key agreement,
while session reset wipes authorization. HID reuses its 192-byte inline area as
its PKE read window. Prepared response reads never repeat crypto or encoding.

minicbor 2.3.0 is an unmodified upstream Git submodule at `third_party/minicbor/`, pinned to
`67b22f849a0ff12b669a0c304236ffe9744f9a79` (the release's recorded source commit).
Initialize it with `git submodule update --init --recursive`. Cargo uses the
`third_party/minicbor/minicbor` package as a path dependency with default features disabled.
The upstream BlueOak-1.0.0 license remains in the submodule.

String lengths use the same CBOR argument encoding as unsigned integers. The
adapter normalizes only their major-type bits in its bounded header buffer and
uses upstream `Decoder::u64` to decode the length. It then streams the body and
validates UTF-8 separately. No local minicbor patch or fork is required.

The adapter buffers at most a nine-byte header, container counters, and one
incomplete UTF-8 code point. minicbor interprets scalars and length headers;
`core::str::from_utf8` validates text. The adapter preserves push input across USB
and ISO APDU fragments. It enforces shortest arguments (except legacy largeBlob definite byte-string
lengths, which accept wider encodings), definite lengths, a byte
budget, depth eight and exactly one complete value. Tags/floats, invalid UTF-8,
truncation and trailing values fail. Consumer failure is terminal; provisional
events never authorize or write storage.

The clientPIN/config roots, recognized COSE maps and config parameter maps
require canonical integer-key order and unique keys. Unknown values are structurally skipped without retaining source
offsets. **Canonical key order in skipped unknown nested maps remains unchecked**;
complete CTAP validation must close that gap. Known fields have protocol-specific
length/type checks. Missing parameters return 0x14, wrong types 0x11, malformed CBOR
0x12, invalid protocol 0x02 and unsupported subcommands 0x3e.

## Transport-specific extended APDUs

CCID accepts short APDU envelopes up to261 bytes and rejects bounded extended
encoding with6700 before applet routing. Oversized XfrBlock payloads drain to
the declared length without PKE or a receive-gap deadline, then return the
command-specific CCID error (valid XfrBlock parameters: bError01). Short ISO
command chaining and streamed GET RESPONSE remain available for PQ operations.
The removed extended-CCID feature and historical tests are pinned in
[the provenance archive](../history/ccid-extended-removed/README.md).

WebUSB admits structurally valid APDUs within a288-byte envelope, with no
large-body exception. It receives the complete envelope in the shared CCID/EP0
IO allocation before parsing, so a superseding SETUP aborts partial RX without
revoking prior selection, PIN authorization or APDU chains. Foreign context
preparation is likewise deferred until complete command dispatch. A completed
transport changes Hold to Idle only after strictly more than2000 ms since the
last WebUSB SETUP; status polls refresh this tick and IN completion does not.
This releases the transport reservation, not the retained applet context.
Pending APDU continuations still block foreign takeover after transport Idle.
USB lifecycle reset remains a separate context-revoking operation.

NFC admits extended Lc<=279 inline to ordinary applet
checks. Above279, only standalone selected FIDO CLA80/INS10 with valid P1/P2
may stage a CTAP body in PKE; non-FIDO requests drain and return6700. Exactly
seven bytes are Case2E (Le, no body) and do not borrow PKE. PIV retains its own
extended-APDU rejection after transport admission.

The current logical CTAP request limit is1296 and matches GetInfo. NFC stores
only the envelope in its261-byte window plus27-byte tail; staged body input
must be parsed and closed before crypto, presence or progress can reuse PKE.
NFC FIDO extended responses aggregate within the current command's Le budget;
finite exhausted Le leaves a continuation for external GET RESPONSE.
An opposite-block-number R(NAK) replies with R(ACK) without advancing output.
R(ACK) advances only a pending response chain; otherwise it is ignored without
resetting selection or partial input. Retransmission uses the last Link packet,
including a control ACK, and never rereads a forward-only response source.

Interrupts publish bounded input; serialized main-loop code owns Core/PKE.
USB/RF lifecycle resets close request/response leases and invalidate stale work.
The common pinned-C boundary matrix is maintained in the platform alignment
plan's `docs/c-3.1.2-extended-apdu-oracle.md`. Physical RF acceptance remains open.

During initial USB enumeration, `composition::usb::service` consumes deferred
CCID/HID/WebUSB reset events on the serialized main loop. It closes leases and
revokes stale authorization without dispatching queued application commands.
Normal transport polls share those reset handlers after boot self-checks.

Unknown CBOR values have an independent four-map/array skip budget, matching
C3.1.2's TinyCBOR build. Known schema parents do not consume it; strings consume
no map/array depth. The incremental decoder retains its separate eight-container
bound. Nonempty malformed CONFIG input reports its CBOR error even when the
first fragment fails; a truly bare CONFIG keeps its legacy status.

## Endianness and USB composition

USB SETUP fields and descriptor multibyte fields are little-endian. The USB core
already converts SETUP to native integers: class routing compares `wIndex` and
`wValue` directly, including on CIU BE8. CCID `dwLength` is also little-endian.
CTAPHID CID and BCNT, APDU extended lengths/status words, and CBOR integers are
big-endian on the wire. CID allocation is monotonic within the current boot;
channels are transport labels, not authentication capabilities.

When enabled, HID is interface 0, CCID is interface 1, and optional keyboard is
interface 2. Without CTAP, the existing CCID/keyboard interface numbers stay
unchanged. All profiles advertise short CCID exchange level0x000200FE, IFSD254
and maximum message271 bytes, independent of CTAP/HID enablement. Short HID transfers are discarded rather than parsing a stale tail.

## Validation

From the core directory:

```sh
cargo +nightly-2026-09-04 test --manifest-path Cargo.toml --workspace --all-features
cmake -S . -B build/rust-host -DCANOKEY_PROFILE=ctap
cmake --build build/rust-host
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
The CCID adapter test covers split headers, literal LE/BE lengths, extended
rejection, indefinite oversized drain, cleanup, reset races and HID contention.
NFC tests cover inline boundaries, PKE sources, retransmission and finite Le. Execution checks cover CANCEL during in-flight
KEEPALIVE, foreign-channel isolation, INIT resync and a stalled control endpoint. CBOR tests use
minicbor-generated vectors at every split, one-byte fragments, all truncated
prefixes, malformed canonical encodings, nesting limits and split UTF-8.

In the CIU parent repository:

```sh
cmake --preset devkit
cmake --build --preset build-devkit
.venv-hil/bin/python tools/hil/devkit_ctl.py --list
# Flash using the parent AGENTS.md workflow, then:
.venv-hil/bin/python tools/hil/rust_ctap_smoke.py --control <control-port> --output <report.json>
```

The read-only HIL checks run 70 PINGs at 0/57/58/192/193/256/1024 bytes, independently
decode GetInfo with python-fido2, check transport errors and CCID ownership, and
check CCID extended rejection, oversized drain/recovery, malformed envelopes
and chain conflicts. Historical extended-CCID successes are archived; NFC
staging requires separate RF acceptance. They create no credentials or PINs.

## Remaining migration and target evidence

Continue with configurable SM2 identifiers and provisioned attestation. Long crypto needs cooperative
progress/cancellation. Unknown credential-map text labels are consumed beyond
the32-byte recognition window. Their complete UTF-8 is validated; equal-length
long unknown names follow C's skip policy without retaining their full spelling.
Bounded labels keep exact ordering checks. RP values must be text and options
must be boolean even for unknown labels. Broader canonical-validation and
source-cancellation review remains open. Preserve the input-close boundary.

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

FIDO APDUs require explicit SELECT-by-name after startup or slot reset.
CTAP2/U2F command headers do not select an applet; unselected short, chained
and standalone extended FIDO requests return `6A82`. Native CTAPHID CBOR
execution remains independent of APDU selection. Large NFC admission requires
an already selected FIDO applet before staging request bytes. CCID rejects
extended encoding before selection checks. Streaming
regressions cover explicit selection, bounded length, owner restrictions,
source cleanup and chain errors.


### Full host HID execution regression

Host CMake builds `hid-core` whenever `CANOKEY_APPLET_CTAP=ON`. Its Rust binary
uses the production HID mailbox/link/framing code and CTAP applet through a
Rust Provider with direct storage/device/staging fakes and native crypto imports.
Packet hardware and monotonic time are simulated; record storage is volatile. APDU-only
fixtures retain their fail-on-use HID stubs and do not substitute for this test.

Run `ctest --test-dir <host-build> -R '^hid-core$' --output-on-failure`. Coverage
includes long echo, source-backed clientPIN crypto, GetInfo streaming, sequence
errors/timeouts with scratch cleanup, execution busy/keepalive/cancel, same-CID
INIT and disconnect response suppression. This is not USB controller, durable
storage or physical interoperability acceptance. The [Rust UDP virtual card](../../crates/host/README.md) uses these same production
runtime with durable host records and runtime error injection. PC/SC and Rust
libfuzzer-sys entrypoints have separate acceptance suites.


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

### U2F and clientPIN size boundaries

U2F accepts only P-256 handles and does not load SM2 provisioning. Missing or
malformed SM2 settings therefore do not gate VERSION, registration or
P-256 authentication; other handle algorithms are rejected before key opening.
Registration exports the public point directly at output offset 2, with the
remaining 526-byte buffer preserving the native generic operation's 512-byte
capacity contract. P-256 signatures are written and DER-encoded in their final
output position through the existing typed signing port. Authentication uses
Prepared backing; registration retains the common certificate-splicing response.

PIN policy-only readers share one complete-record load/validation/erasure path
and return just the four public policy bytes. This is not a policy cache or a
partial-record read: malformed records and I/O failures still fail closed, and
configuration changes apply on the next command. Credential/config/PIN mutation
paths retain the full record where they need its hash or RP list.

clientPIN and hmac-secret share private agreement-key preparation. Lazy ECDH
initialization generates the key without exporting a discarded public/COSE
response; getKeyAgreement exports the cached key when requested. The fixed
81-byte status-plus-COSE response uses typed coordinate/output capacities.
MAC verification shares one native output, comparison and audited erasure;
callers retain protocol/tag-length, permission, RP binding and expiry checks.
Primitive failure remains Other, distinct from PinAuthInvalid. Key-generation
failures flow through command workspace cleanup and session invalidation.

### Parser and resident-record size boundaries

Private request layouts group scalar metadata before contiguous byte buffers;
these layouts are neither native ABI nor persistent record formats. Preserve
measured field order when changing them: fewer source initializers do not imply
fewer Thumb-1 instructions. Credential finish transfers an owned parameter copy,
clears the source buffers and invalidates its required-field mask. It does not
move the entire parser onto the stack or borrow PKE-backed input. Copy on the
credential/hmac parameter types supports this explicit transfer; source and
command erasure remain separate lifecycle requirements.

Strict resident scans share record loading and decoding. Callers keep their
original ordering, UV/algorithm filtering, RP grouping and cursor advancement.
Management's metadata counter retains its different behavior for malformed
records, so it does not use the strict reader. No record-count cache is added.
Attestation callers share exact key-length and required-certificate checks,
while retaining their storage-call order, self-attestation rules, status mapping
and secret cleanup. Signature paths remain separate after size measurements
rejected a combined signing/DER wrapper.

### ML-DSA response streaming correctness

ML-DSA public keys use the AKP COSE map `{1: 7, 3: algorithm, -1: public_key}`
for registration and credential management. DSA65 uses algorithm-49/public1952/
signature3309; DSA44 uses-48/public1312/signature2420. Label-1 carries public
bytes; AKP has no OKP curve field or label-2 coordinate. Parameter metadata is
shared by GetInfo, key selection, public encoding and streamed output. SM2
configuration rejects both PQ COSE IDs. Full GetInfo algorithm order is
`[-7,-8,-49,-48,SM2]`; restricted profiles retain `[-7,-8]`.

ML-DSA makeCredential uses the same extension encoder as classic credentials,
preserves UP/UV/ED flags and one counter increment, and splices the public bytes
after the COSE header and before extensions. The P-256 attestation hash covers
that exact authenticatorData; its DER signature is inserted once. Assertion
framing includes CTAP status, credential descriptor, resident user data and
largeBlobKey, and accounts for authenticatorData when moving into the shared
stream workspace.

Credential management encodes directly from the shared resident input record,
including maximum user fields, before reusing that input for its ML-DSA seed.
The shared Working reservation separates persistent response framing from an
inner Primitive enum: classic key/input/SM2 agreement and opaque PQ state are
mutually exclusive. Classic applets receive a temporary Workspace borrow; its
528-byte output aliases the beginning of the existing 768-byte framing buffer.
Stream::transfer retains that output in place, inserts assertion authenticatorData
between its prefix and suffix, and copies the adjacent client hash and seed into
one 64-byte retained region. It wipes the classic primitive and unused framing
before initializing CryptoScratch in the inner enum. No framing-sized stack
object or second output buffer bridges this transition. Retained hash/seed bytes
are wiped after initialization on success and failure; close aborts the primitive
and clears framing, material and counters. The transfer frame returns before
primitive initialization; the crypto state remains in the sole shared workspace. Full enumeration returns the registration public key; metadata-only
mode omits it. No second full public-key buffer or Flash scratch is introduced.
`ctap-normal` independently verifies packed attestation and ML-DSA signatures,
decrypts hmac-secret-mc results and compares full/metadata mixed enumeration.
Hardware stack measurements remain required for the repaired call paths.

Firmware HID CBOR/MSG and APDU execution finish parsing and dispatch in a
separate frame before preparing a pending PQ response. This releases the
large parsed command object before ML-DSA stream initialization and signing.
HID MSG's requested response window and final APDU status cross that boundary
as scalar values; response backing stays in the same shared workspace. The
transport execution guard still covers both stages, including keepalive and
cancellation. Classic crypto still runs while its semantic command is live;
this boundary does not establish a bound for all crypto call paths.

Applet deselection clears both resident assertion and credential-management
continuations as well as volatile PIN authorization and key agreement. The
`ctap-normal` APDU fixture verifies this through SELECT ADMIN / SELECT FIDO,
then confirms management works after fresh clientPIN authorization.

GetInfo advertises `pinUvAuthToken: true` for permission-scoped clientPIN
subcommands, alongside PIN protocols 1 and 2. This option lets clients select
the supported permission-scoped authorization flow rather than legacy tokens.

Credential-management delete propagates storage removal failures as CTAP 7F
and revokes volatile authorization through the common failure path. A failed
removal must not be reported as success; retry requires fresh PIN authorization.
Host coverage verifies preserved records after rejected replacement/deletion
and session reset, but does not establish LittleFS power-loss atomicity.

### HID MSG response windows

HID MSG preserves Le for both CTAP and U2F responses. Absent Le returns the full
response; encoded zero follows the APDU format maximum. A limited response ends
in 61xx and retains its backing in the shared session workspace. GET RESPONSE
accepts ISO/proprietary CLA, absent/short/extended Le and the legacy nine-byte
empty-Lc form. Other nonempty-data forms are rejected; general APDU parsing is
unchanged. Exhausted or abandoned continuations return 6986.

Only acknowledged final HID IN completion advances the response window. A
continuation parses its bounded header without overwriting the shared workspace.
New commands, malformed continuations, INIT, channel changes, transport reset
and cross-transport preemption discard pending backing. New PKE-staged input
closes the preceding response before borrowing accelerator scratch. HID cleanup
checks core ownership so it cannot close another interface's response.

`hid-core` compares full case 3/case 4 responses against native CBOR, checks
limited/multiple windows, held-IN completion, file-backed payloads and aborts.
`usb-sessions` verifies that CCID/WebUSB cannot take over a pending HID
continuation across two3000ms gaps, and that takeover becomes possible after
the final response completes. Two word-sized window fields are added to the
applet; no private response buffer or protocol implementation is moved to C.

Provisioned attestation certificates must contain 1..1152 bytes. With a provisioned key, an
empty certificate is rejected by classic and ML-DSA makeCredential with CTAP
7F and by U2F registration with 6900; no partial registration response remains.
The existing configuration fixture checks both CTAP algorithms fail and recover
after valid ADMIN reprovisioning, with independently verified packed signatures.
The U2F fixture separately checks empty-certificate rejection. This validates
use-time rejection, not the legacy install-time incomplete-state rebuild.

Classic makeCredential only falls back to self-attestation when provisioned
material is genuinely missing. Attestation-key read errors and malformed key
lengths return CTAP 7F; they must not change the attestation mode. Temporary
attestation-key bytes are wiped on certificate/key validation errors as well as
success. `ctap-config` injects a read that supplies key bytes then reports I/O
failure, checks rejection/no pending response and independently verifies a fresh
packed attestation after the fault clears.

### Optional credential algorithm restriction

The `ctap-restrict-algorithms` Cargo feature (CIU CMake
`CTAP_RESTRICT_ALGORITHMS=ON`) retains the existing optional policy. GetInfo
advertises only ES256/Ed25519; makeCredential chooses the first permitted RP
algorithm or returns UnsupportedAlgorithm (26). Allow/exclude lists and
discoverable assertion enumeration ignore existing SM2/ML-DSA credentials;
authentication with only such credentials returns NoCredentials (2e).
Credential management still lists their original public keys and can delete
them. Persistent records and U2F's P-256 path are unchanged. Full production
presets leave this option OFF; restriction is not a firmware-capacity solution.

The existing `ctap-normal` test also runs a separately compiled restricted
host: real five-algorithm credentials and their master/resident records cross
the build boundary, followed by registration fallback, independently verified
allowed signatures, resident continuation filtering and authenticated management.
`RECORD` is an in-process host fixture control, never a firmware APDU.

### Reader logical power versus device reset

CCID PowerOn/PowerOff and virtual PC/SC PowerICC clear APDU selection,
authorization, key agreement, continuations and pending responses. Clients
must SELECT again and obtain fresh authorization. Durable records and the
device power-on timestamp are preserved; slot reset does not restart the
authenticatorReset power-on window. Active foreign transport ownership is
protected by the transport's power-command admission checks.

The PC/SC fixture checks warm reset and power-down/up rejection before SELECT,
then recovery after reselection. Mixed GA/CM enumeration stays within one
session. The replay lifecycle test verifies agreement and token revocation.

### Boot reconstruction of incomplete provisioning

Core installation validates attestation key length/readability, certificate
length (1..1152), and the provisioned SM2 identifiers before admitting commands.
Missing or malformed manufacturing prerequisites erase CTAP master, PIN/policy,
counter, largeBlob and resident credentials as in the legacy startup contract.
Sparse absent records represent fresh default state; the next successful
registration signs counter one. Valid SM2 identifiers survive; invalid/missing
SM2 is repaired only after erasure succeeds. Attestation material is retained
for explicit ADMIN reprovisioning. Use-time self-attestation remains possible
on an unprovisioned device, but those credentials do not survive this boot gate.

A storage error that prevents validation fails installation without deleting
records. Failed cleanup also fails installation and leaves its invalid
prerequisite in place so the next boot retries. This differs deliberately from
treating transient I/O errors as proof that valid credentials should be erased.
Logical reader power cycles do not invoke the boot installation gate. The
existing configuration fixture tests actual credentials, signed counters, PIN
removal, SM2 preservation/default repair and read/cleanup failure recovery.

An omitted or empty getAssertion `allowList` discovers resident credentials.
A nonempty list with no usable matching IDs returns `NO_CREDENTIALS`; it must
not fall back to discovery. The shared mixed-algorithm fixture checks both
discovery forms and rejects an unknown nonempty list.

For admitted makeCredential/getAssertion requests, empty `pinUvAuthParam` is a user-presence-gated
PIN-state probe even when `pinUvAuthProtocol` is omitted: it returns `PIN_INVALID`
when a PIN exists and `PIN_NOT_SET` otherwise. Nonempty authentication requires
a protocol; a protocol/authentication-length mismatch returns `PIN_AUTH_INVALID`.

Credential options are command-specific: makeCredential rejects explicit `up`
with `INVALID_OPTION`, and getAssertion rejects explicit `rk` with
`UNSUPPORTED_OPTION`, regardless of their boolean value. Omitted options retain
the command defaults; getAssertion continues to support `up: false`.
Both shared parsers apply these command-key rules after boolean type validation.
Silent getAssertion with hmac-secret returns `UNSUPPORTED_OPTION` before PIN-policy
IO, RP hashing, presence or token verification, even with empty authentication.
Other invalid semantic options also reject before that PIN-state probe. The
shared authorization engine has no ordering profile; the Core adapter validates
before loading PIN policy. Full dispatch can still load product SM2 settings.
Request rejection leaves existing agreement/token authority intact and the
outer credential owner erases workspace input, output and key bytes.

Resident getAssertion/getNextAssertion enumeration preserves the legacy descending
record-slot order. The cursor is an exclusive upper slot bound, including slot
zero without underflow. Credential management retains its separate scan order.

Successful boot installation restores the volatile three-attempt PIN allowance
without changing durable retries. Transport/session reset and CTAPHID INIT do
not clear temporary lockout. The UDP fixture verifies lockout across INIT and
recovery after a real simulated reboot, including durable retry preservation.

A successful `getAssertion` with `up: false` preserves token permissions for
subsequent assertions. An assertion with user presence consumes permissions
except large-blob write. RP binding, token expiry and UV checks apply to both
paths; rejected RP mismatches neither authorize nor consume the valid token.

Unused RP `name` and `icon` metadata must still be CBOR text; the parser
validates their types without retaining them. HMAC-secret salt ciphertext must
encode one or two 32-byte salts (plus the protocol-2 IV); invalid sizes return
`INVALID_LENGTH`. Authentication and key-agreement validation are unchanged.

A largeBlob fragment rejected with `INVALID_SEQ` leaves the accepted upload
prefix and expected offset intact. A corrected authenticated fragment can
continue; a corrected offset exceeding the declared length returns
`INVALID_PARAMETER`. Other upload errors still abort staging, and uncommitted
bytes never replace the durable blob.

Credential management checks required inputs before token verification: missing
authentication returns `PUAT_REQUIRED`; missing protocol or required RP,
credential or user fields returns `MISSING_PARAMETER`. With required fields
present, invalid authentication (including a protocol/length mismatch) returns
`PIN_AUTH_INVALID`. Continuation commands retain their existing cursor checks.

Resident RP display IDs retain at most 32 bytes. Long IDs preserve a scheme
prefix through the first colon when present, then an ellipsis and suffix when
space permits. UTF-8 characters are never split. RP hashing and authentication
use the complete input ID. Unknown CTAP CBOR commands retain the legacy
`UNHANDLED_REQUEST` status (0xf1), including unsupported biometric enrollment.

### Resident mutations and RP enumeration

Credential-management user updates, like deletion, return CTAP `Other` (7F) on
failed or uncertain publication. The common failure path revokes volatile
authorization and continuations. An error does not prove that the write did not
commit: reauthorize and enumerate before deciding whether to repeat the update.
An identical encoded record is acknowledged without a persistent write.

CTG1 record bytes and the 100-slot capacity are unchanged. Equal-length updates
use one atomic `Storage::replace_at` transaction. Size changes, insertion and
multi-member deletion buffer the three unchanged members in the existing shared
key workspace, then publish a staged group. Reads must finish before staging:
interleaved record reads close the backend's shared-cache stage lease and cause
extra commits. Creation preserves the ECC key view/PQ seed while lending the
unused RSA tail; copied credentials are wiped on completion or failure. No new
static credential buffer, persistent index, journal or format migration is used.
Size-changing mutations still copy the group; reduced backend writes are not a
claim of a particular Flash service life.

RP_BEGIN builds a representative-slot bitmap using batches of 40 complete
32-byte hashes in the shared key workspace and group-header-cached scans. At
most three passes are needed for 100 distinct RPs. The bitmap replaces the old
visited bitmap without growing the session; RP_NEXT reads only its next selected
slot. Hash storage is erased by command cleanup and does not survive responses.
New commands, errors and applet/session reset discard the continuation.

Unit coverage bounds index construction to 270 Storage calls for a full store,
checks full-hash equality, ordering, sparse groups, no persistent writes, maximum
peer-copy capacity, no-op/patch mutations, staging failures and an uncertain
commit that actually took effect. `ctap-normal` checks same-size and size-changing
update rejection, reauthorization, reset persistence and normalized no-op updates.
CIU's storage-cost fixture separately compares physical programs and erases
against the historical interleaved-read publication path.

NFC staged input checks both execution liveness and activation generation around
source reads and after source cleanup. Runtime closes the source exactly once
before applet execution; a close failure prevents execution even after complete
parsing. This includes HALT during PKE clear/release and deselect without a new
generation. Reader failures return APDU6900; cancelled activations suppress the
APDU response while deselect retains its protocol echo. IRQ callbacks only
update transport state and never reenter Core or release its active source.

Coalesced HALT/ACTIVE interrupts read the live RF state after error/overflow
checks. States9/10 (RATS/PPS) supersede the older HALT: the new activation
revokes the old session and preserves its newly received frame. Other states
retain HALT priority; a failed state read cannot publish FIFO bytes. Forced
RF silence masks all active-high MAIN IRQ sources with0xFF. Recovery drains
latched IRQs and restores the runtime mask only after unsilence, including when
the mask write failed.

Queued input retains its RF reply turn after the main loop takes its bytes,
including while Request::append writes to PKE. Bounded overlapping FIFO frames
are drained through a local32-byte IRQ window without decoding or replacing
that input. Invalid hardware lengths and bus/IRQ errors still trigger recovery.
An ignored unsolicited ACK releases its turn without resetting Core. The same
pending-turn guard drains early reader frames while Core executes, until an
APDU response or WTX is actually transmitted. A matching WTX echo permits the
response; IRQ/field errors may still revoke execution. A deselect after WTX
cancels the command and retains its protocol echo for main-loop service.
Wrong echo/ACK/NAK/deselect after WTX still differ from pinned C's permissive
continuation. Those cases, WTX retransmission-cache semantics and physical
IRQ/RF timing acceptance remain explicitly unresolved.


AuthenticatorData construction shares one public-before-extension sequence in
`canokey_ctap::response::auth_data`. Complete classic public preparation and COSE
encoding before extension admission and ED; primitive/public-output failure
leaves ED clear. The streamed PQ branch returns after its fixed header and its
existing output owner invokes the shared outlined extension stage after public
output. Failed extension output is provisional and must be erased by the outer
owner before returning an error. Signing/publication require successful assembly;
no separate complete response or key buffer is introduced.


ClientPIN required/scope admission uses the shared `request::admit` without a
product ordering profile. After structural and individual field checks, require
command fields before rejecting forbidden legacy-token scope or missing RP for
permissioned MC/GA tokens. A legacy getPINToken request missing agreement/hash
and carrying scope reports MissingParameter; a complete legacy request with scope
reports InvalidParameter. The admission engine performs no crypto, storage,
presence or token mutation. Product permission capabilities remain explicit.
