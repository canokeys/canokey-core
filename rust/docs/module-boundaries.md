<!-- SPDX-License-Identifier: Apache-2.0 -->
# Full Rust core migration: module boundaries and service contracts

Status: migration architecture and implementation ledger, updated 2026-09-23.
The independent zero-applet USB target and the first ADMIN + PASS checkpoint
are implemented. OATH now has an APDU-free domain, a common-APDU adapter,
concrete storage, USB integration and normal host/device validation. OpenPGP
now has a real optional profile, streaming import/certificates and all existing
algorithm families; see [OpenPGP implementation](openpgp.md).
Design coverage for the remaining applets is not feature support.
The 2026-09-23 C streaming review in section 14 constrains the next refactor;
section 12 records implementation order and completed foundation work. Long
consumer fixtures exercise the production runtime. PIV remains absent; the
OpenPGP profile now supplies real key/object consumers on that foundation.
See [ADMIN/PASS checkpoint](admin-pass.md) for its supported commands and gaps.

Scope: the complete current core, including ADMIN, PASS, OATH, CTAP2/U2F, PIV,
OpenPGP and NDEF, over USB CCID, WebUSB, CTAPHID, keyboard HID and NFC as
applicable. NFC is a transport; NDEF is an applet. CIU changes stay limited to
interfaces/backends; startup, vectors and recovery remain C. NFCC is deferred.

### Migration compatibility rule

This is an implementation-language rewrite, not a product-policy redesign.
Preserve existing AIDs, commands, data formats on the wire, authentication,
defaults, retry rules, algorithms and counter order unless the user explicitly
approves a behavioral change. Internal layout changes must be documented and
must not silently reinterpret legacy records. No unsolicited KDF, PIN hashing,
salt, enrollment protocol or extra presence requirement may be introduced.
ADMIN retains default PIN `123456` and three retries, with the C comparison and
retry-update behavior. The mistakenly introduced PBKDF2 experiment was removed.

Incomplete commands remain tracked work, not approved feature removals. In
particular, Rust ADMIN is not complete merely because PASS management works.
Other applets stay absent from the selected build until explicitly introduced.
Normal functional tests and build/link/boot checks are the verification scope;
no boundary, differential or fuzz campaign is added implicitly.

## 1. Responsibility model

| Module | Owns | Does not own |
| --- | --- | --- |
| C transport interfaces | USB enumeration, CCID/WebUSB/CTAPHID/NFC framing, endpoint buffers, link timers and transfer completion; keyboard HID encoding/report sequencing | APDU parsing, SELECT, authentication, slot selection, OTP calculation |
| Rust FFI boundary | Pointer/length validation, serialized access to the root runtime, C error conversion, alias-safe borrows | INS dispatch, credential policy, persistent record interpretation |
| Common protocol | APDU syntax/chains/response planning; bounded TLV and CBOR structural decoding/encoding | AIDs, CTAP command schemas, credential limits, storage, transport arbitration |
| Rust runtime | Transport-independent operation ownership, APDU selection, progress/cancel/presence events, resource leases and cleanup | PASS slot rules, PIN comparison algorithm, filesystem record layouts |
| Applet registry | Explicit build-time applet set, AID/native-protocol binding, delegation to typed applet adapters | Protocol parsing algorithms, implicit installation of other applets |
| Applet protocol adapter | APDU INS/P1/P2, CTAP commands and schema interpretation, semantic fields, protocol error/status mapping | USB details, common APDU parsing, crypto implementation |
| Applet domain/service | Slot/credential/key/object rules, authorization requirements, application-specific commit order, semantic results | APDU structs/SW, raw C pointers, USB packets, native struct persistence |
| Shared services | Authentication mechanisms, opaque storage contracts, crypto capabilities, secret-memory utilities, common input/output types | Applet wire commands, global authorization for unrelated applets |
| Platform backends | Filesystem operations, flash I/O, primitive crypto, RNG, touch sensing, USB report transmission | Applet record schemas, PIN retry policy, first-use enrollment policy |

C remains the transport/platform boundary. Existing C LittleFS and primitive
crypto implementations can remain backend dependencies during this rewrite.
They are explicit low-level dependencies, not permission to link C ADMIN, PIN,
PASS, OATH, `src/device.c`, `src/apdu.c`, or applet installation routines.

Logical module boundaries do not require one crate per row. Start with modules
inside the existing crates; split a crate only when dependency enforcement or
reuse justifies it. No dynamic applet registration, heap-backed registry,
general event framework, or async executor is required.

## 2. Dependency direction and assembly

```mermaid
flowchart TD
    C[C transport] --> F[Rust FFI]
    F --> R[Runtime and explicit registry]
    R --> P[Common APDU TLV and CBOR]
    R --> A[Applet protocol adapter]
    A --> P
    A --> D[Applet domain and services]
    D --> S[Shared service contracts]
    F --> B[Backend adapters]
    B --> S
    B --> H[C platform primitives]
```

Arrows express source dependencies/calls to abstractions. The assembly root
provides backend implementations to services; an applet never imports an FFI
adapter. The common protocol layer cannot depend on an applet. Shared services
cannot depend on applet implementations or emit APDU, CTAP or transport status codes.

APDU and native CTAP are separate entry paths into the same runtime. Native
CTAPHID CBOR must not be wrapped in a fabricated APDU to fit an APDU-only engine.
A FIDO APDU adapter and a CTAPHID CBOR adapter converge on typed FIDO operations;
U2F retains its own message schema. Shared logic does not imply identical wire
responses or authorization assumptions across transports.

A build-time enum/explicit match assembles enabled applets. The runtime asks
that registry for selection, request limits, command consumers and response
sources. It must not contain PASS-specific constants, direct PASS response calls,
slot indices or algorithms. A zero-applet registry is a real empty build. The ADMIN + PASS profile
must not link OATH, and applet count describes compiled applets, not
services such as PIN verification.

Organization after the 2026-09-23 foundation refactor (future applets are not created):

```text
rust/
  Cargo.toml                 # one workspace; not a workspace per small component
  protocol/src/
    apdu/                    # envelope decoder, chain metadata, response planning
    tlv/                     # incremental BER and byte-TLV structural primitives
  core/src/
    runtime/                 # session, exchange lifecycle and static routing
    applets/
      admin/                 # ADMIN wire adapter and management policy
      pass/                  # slot domain, record codec, repository and output rules
      oath/                  # wire adapter, domain, auth, codec and repository
      piv/                   # future: PIV adapter, streaming consumers and policy
      openpgp/               # future: OpenPGP adapter, consumers and policy
      fido/                  # future: APDU/native adapters and CTAP/U2F policy
      ndef/                  # future: Type 4 Tag application/file semantics
    flows/                   # explicit cross-applet reset and HOTP-output workflows
    ports/                   # narrow storage/crypto/presence/device contracts
  ffi/src/                   # unsafe C ABI and platform backend implementations
interfaces/rust-core/        # retained C transport adapters and public ABI header
```

Applet-local `protocol`, `domain`, `codec` and `repository` modules remain
separate responsibilities but live together. Domain modules do not depend on
APDU/SW or USB. ADMIN owns the PASS configuration wire commands; OATH owns its
binding wire commands; both call the same typed PASS service. PASS does not need
an invented selectable AID. Common APDU definitions remain in `protocol`.
Features are explicit; board profiles assemble dependencies rather than using
an OATH feature to implicitly install unrelated applets. Registry only routes;
factory reset and HOTP keyboard orchestration belong to typed cross-applet flows.
No per-applet crate or generic dynamic plugin framework is required.

## 3. State and lifetime ownership

| State | Single owner | Lifetime/end condition |
| --- | --- | --- |
| CCID receive/transmit packet buffers | C transport | Endpoint transfer; RX borrow ends before reuse |
| Operation owner `(transport, connection/channel, generation, operation)` | Rust runtime | Operation release, reset, cancellation or validated handoff |
| Idle transport/channel bookkeeping | C transport | Link/channel expiry; does not own applet scratch |
| Selected applet | Runtime | SELECT/reset; registry identifies the target |
| Command header/chain metadata | Runtime using common protocol | Command completion, abort, replacement or reset |
| Parsed command fields and TLV decoder | Selected applet command state | Final fragment/abort; secret fields wiped |
| Response cursor and source lease | Runtime | Completion, replacement, read failure or reset |
| Response backing data | Applet/repository leased by runtime | Immutable until lease closes |
| Persistent credential/slot records | Rust repository/codec over storage backend | Explicit successful durable update |
| PIN retries | Authentication service over credential repository | Durable protocol-specific attempt/reset policy; no grant on uncertain persistence |
| Session-local grants | Runtime session context with applet policy | Reset/owner change/logout/change/deselect as specified for that grant |
| CTAP token/challenge state | Typed authentication mechanism under runtime lifecycle | Protocol-defined permissions, expiry and invalidation; not a global PIN boolean |
| Multi-command continuation (assertion enumeration, key agreement, file update) | Applet operation context leased by runtime | Explicit continuation completion/abort; never confused with response pagination |
| Pending keyboard output and output policy | Rust output job | Completion, cancellation or disconnect |
| Current HID report in flight | C HID transport | Transfer acknowledgement or endpoint teardown |

Persistent state is not erased by ordinary session cleanup. Loading/validation
is distinct from recovery: `boot/load` must never format a filesystem or treat
a corrupt record as an empty configuration. The ADMIN compatibility profile
explicitly initializes an absent new PIN record to `123456`, matching C ADMIN.

Only the main loop calls Rust or platform callbacks that might enter services.
Interrupts record transport/input events. A USB reset must not release a buffer
still borrowed by Rust; it queues cleanup and invalidates the generation. The
current CCID adapter follows this arrangement. No callback may reenter Rust.

Physical events, native CTAP requests and APDUs share one scheduler. A touch
requested by the active operation is delivered to that operation; it cannot
also trigger PASS typing. An unsolicited PASS trigger must not bypass another
operation's resource lease. The current profile rejects APDUs with 6985 while keyboard output drains, and
discards PASS gestures during APDU chains/pending responses. A future shared
Busy indicator must require another touch
rather than queue an unbounded or stale secret-output request. HID completion only advances
an existing output job. Wall-clock time is supplied by the platform; the runtime
owns operation deadlines and timeout-triggered cleanup. C interfaces own link
fragment/retry/WTX timing within an armed transport lease; they cannot extend
credential grants or decide to resume/cancel a business operation.

## 4. APDU command and response lifecycle

Conceptual lifecycle; concrete Rust traits/borrowing should follow this design,
not force a self-referential struct or one permanent large buffer per applet:

1. Transport supplies a bounded frame or, later, a bounded frame fragment.
2. Runtime establishes owner/generation, applies the transport profile and uses
   the common APDU decoder. The current device profile remains short APDUs plus
   ISO command chaining; extended transport admission is a separate capability.
3. SELECT-by-AID uses the registry. A new command closes the previous response
   and aborts its unfinished input. Resolve AID before changing selection: an
   unknown AID preserves the current selection/grants. Switching to a known
   different applet revokes old selection-bound grants; initialization failure
   leaves no selection. OATH same-AID selection renews its challenge/session. Applet-local SELECT FILE (notably NDEF/OpenPGP) goes to that applet;
   not every INS A4 changes the selected application. Same-AID reselection and
   logical-channel support are explicit protocol-profile choices.
4. The selected adapter validates the command header and starts a typed command
   consumer. Runtime checks chain consistency and enforces the declared budget.
5. `feed` consumes ephemeral bytes into bounded semantic fields, a TLV consumer
   or a specifically authorized storage stream. It never retains transport slices.
6. `finish` validates the request and starts or completes a typed operation.
   Retrying PIN checks, HOTP reservation and other commit points follow explicit
   operation policy. A long operation advances through the runtime lifecycle
   below; the adapter eventually maps its typed result to SW and response data.
7. Runtime owns response offsets, Le/61xx and GET RESPONSE. A typed source reads
   stable data by offset and closes exactly once. Applets do not implement their
   own saved-tail buffer or GET RESPONSE handler.
8. Replacement/reset/error closes leases and wipes transient secrets. A malformed
   continuation aborts the command. GET RESPONSE during an unfinished input chain
   aborts that chain and does not authorize completing it later.

Use an explicit response-source enum/handle if needed to borrow the applet only
for each read; do not retain a mutable reference into the runtime itself.
A single session scratch lease can later serve large applets. PASS's 64-byte
prototype buffer is an applet bound, never a global APDU maximum.

TLV emits structural events only. Each applet supplies its allowed tags,
duplicates, ordering and value rules. PASS's current configuration wire format
is not TLV and must not be wrapped in TLV solely for architectural uniformity.

## 5. Narrow service contracts

These are semantic contracts, not frozen C function signatures. Split the current
`Platform` trait into capabilities. A service receives only the capabilities it
uses; do not replace it with a bag containing every platform operation.

### Storage and repositories

A generic storage backend accepts bounded opaque keys and bytes. Rust owns key
namespaces and record schemas. Replace numeric platform file IDs 0/1 with typed
Rust keys mapped to bounded backend keys at the adapter. C need not know that a
key contains PASS slots or PIN retries.

Initial capabilities: lookup/read-at, bounded atomic replace and removal. Reads
report NotFound separately from Corrupt/IO. A successful replacement means the
whole record is durable. A failure must distinguish a known uncommitted outcome
from an uncertain outcome; callers cannot assume every error preserved old data.
After an uncertain outcome, disable the affected operation and reload/validate
before serving it again. Authentication never grants access on an uncertain write.

Use one small atomic record per consistency unit. Credential data and retry
metadata are committed together. PASS configuration is updated as one record.
Large future objects may use an explicit staged-write/commit/abort API; no such
transaction is exposed to an applet until authentication and resource lifetime
requirements are established. Avoid a general multi-record transaction manager.

The filesystem adapter may implement replacement with temporary-file, sync and
rename operations only after their exact durability/error semantics are checked
against the pinned LittleFS implementation. The interface contract is not proof
that the backend already provides it. Backend buffers use fixed storage.

New records use explicit byte order, version, length and bounded fields; no
native enum width, host endianness or Rust/C struct images. The old 142-byte PASS
layout belongs in a future explicit migration codec if compatibility is chosen.
New storage occupies a separate namespace and cannot silently reinterpret or
mutate legacy applet records. Namespace separation is not encryption.

In the CIU port, existing `platform/storage/lfs_config.c::littlefs_init` reformats on mount failure.
It must not be called unchanged by this target. Mount failure is reported; only
an explicit provisioning/reset workflow may format storage. Ordinary SELECT,
boot, missing files or record decode failures never trigger formatting.

### Crypto, RNG and secret memory

Separate hash, MAC and random capabilities. Algorithm/key-size support is typed;
there is no universal `crypto(op, void*)` ABI. Backend failures are explicit
results, including RNG failure; outputs become usable only on success. Correct
error conversion belongs at the FFI adapter, and SW mapping at the applet adapter.

Rust owns authentication/OTP sequencing and protocol-required KDFs (for example
CTAP PIN/UV), without introducing a KDF for ADMIN PINs. C can supply the existing checked
primitive implementations. Clear temporary secret material on both success and
error. A small audited secret-memory utility centralizes non-elidable wiping;
it is not a requirement that every platform supply a PASS-specific wipe callback.
No heap allocation or logging of PINs, keys, passwords or output text.

### Authentication and authorization

Keep three responsibilities distinct:

- Authentication service verifies a named credential, maintains its durable
  retry state, changes its credential and returns typed success/failure evidence.
- Runtime stores session-local grants bound to credential ID, applet scope,
  operation scope and session generation. Such evidence cannot outlive that
  session. A host-supplied CTAP token is revalidated by its typed mechanism for
  each request; its protocol lifetime is not automatically a CCID PIN lifetime.
- Applet policy declares which grant an operation requires. PASS configuration
  authorization does not imply OATH credential access or authorization to type.

Do not use one global `authorized` boolean, export a C `pin_is_validated` hook,
or make a successful SELECT an authentication event. OATH's challenge/
response authentication need not be forced through the same PIN mechanism;
it can issue separately scoped evidence through the same session machinery.

ADMIN PIN verification follows the C mechanism described below. Grants are
issued only after any required persistence succeeds. Secret comparison without
early exit and secret cleanup are shared utilities. Policy limits belong to the
credential definition, not the common APDU parser. Domain errors such as
InvalidCredential, Blocked, RemainingRetries and StorageFailure carry no SW. Other credential mechanisms must preserve their protocol-specific
retry rules, temporary/permanent blocking distinctions and reset semantics; do
not impose PASS's proposed retry policy on CTAP, PIV or OpenPGP.

The rewrite preserves the C PIN mechanism: store PIN bytes and length, compare
without an early exit, decrement persisted retries on mismatch, and restore
retries on a successful verification only when necessary. No PIN hashing, salt,
KDF or new enrollment protocol is introduced by this migration. The record
codec is explicit and versioned, with atomic PIN/counter replacement. Applet
policy still owns minimum/maximum lengths and retry limits.

### Provisioning

The user confirmed that this rewrite preserves C ADMIN's default PIN behavior.
On first installation, an absent `/rust/admin-pin` record is initialized to `123456`
with three retries. Existing valid records are loaded unchanged. Corrupt records,
I/O failures and failed mounts fail closed; they must not trigger default-PIN
creation or filesystem formatting. No new physical-enrollment protocol is added.
This deliberately preserves the original missing-record initialization policy;
it does not detect deletion of a record by an attacker with raw storage access.

Only ADMIN owns this initialization policy. PASS has no PIN or enrollment
protocol. A new namespace does not migrate or replace legacy C credentials.
Changing the default or introducing authenticated migration is a separate product
change, not an incidental consequence of changing implementation language.

### Touch, keyboard and OATH

C reports physical input events (edge/timestamp or a documented debounced event),
not a slot number selected by an applet rule. Rust interprets gesture/slot binding,
checks allowed device/session state and starts a PASS output job. Touch to type
can intentionally work without a configuration PIN grant; that is explicit PASS
policy, not reuse of the configuration grant. When an active FIDO/PIV/OpenPGP
operation is awaiting presence, that operation has priority over PASS gestures.

PASS returns typed output intent/text; it knows no HID usage codes. Rust owns
the output job and choice of configured keymap. C HID interface code performs
character-to-usage conversion and key-down/key-up report sequencing. It accepts
one bounded output item at a time and reports Ready/Busy/Complete/Disconnected;
it neither selects a PASS slot nor obtains a whole password from an applet.
A callback cannot call Rust: the main loop delivers completion events. Keymap
record semantics remain Rust-owned; C receives a validated mapping/profile.
Thus the old `kbdhid.c` loop, which calls C PASS and stores the full secret text,
is not reusable unchanged. Its mapping/report machinery can be extracted and
the low-level endpoint implementation reused, keeping the interface in C.

The Rust output job retains only bounded necessary secret data and wipes consumed
or cancelled data. The C interface clears its current item/report at completion
or teardown; it cannot retain borrowed Rust pointers after a call returns. Disconnect cancels the job; a connected cancellation must release
held keys. Never repeat a password automatically after reconnection. Tests use
a controlled capture sink. Do not infer keyboard success from USB acceptance
alone; it is distinct from acknowledgement of a complete output job.

With the OATH feature, the registry wires a typed OTP service into PASS.
PASS stores a stable credential identifier, not an OATH file offset, raw key or
APDU. OATH owns lookup, key access, calculation and counter policy. Reserve an
HOTP value by durable counter advancement before releasing output; cancellation
may consume a value but must not permit replay through automatic retries. The
registry resolves the stable ID and calls the typed OATH calculation service.
The PASS crate itself does not depend on OATH.

### OATH compatibility contract

The Rust OATH domain is the APDU-free `oath/` crate. `core/src/applets/oath/protocol.rs`
delegates to it, retaining the existing OATH AID and commands. See
[OATH checkpoint and command inventory](oath.md) for exact implementation status.

- Preserve HOTP preincrement: read counter, add one, persist it, then calculate.
  This intentionally produces RFC 4226 counter 1 for an initial counter of zero.
- Preserve SHA-1, SHA-256 and SHA-512, 4–8 digits, 1–64 byte names/keys,
  and TOTP challenges of 1–8 bytes. No algorithm is silently dropped.
- The increasing property accepts equal challenges, requires eight bytes and
  compares their big-endian value. Touch and access-code authentication remain
  independent of ADMIN PIN authentication.
- OATH access-code SELECT/SET CODE/VALIDATE uses the existing 16-byte key,
  eight-byte device challenge and HMAC-SHA1 mutual proof. No password KDF is
  added. The host's derivation of an access code is outside firmware scope.
- OATH fields use the C wire encoding: one-byte tag/length, with the special
  property tag followed directly by its flag byte. Do not reinterpret that
  field as BER length or rewrite host-visible encodings for parser convenience.
- LIST/CALCULATE ALL/SEND REMAINING need a bounded cursor and existing A5/61FF
  continuation behavior. A response continuation must not repeat a counter
  update, MAC calculation or presence action.
- CALCULATE ALL and individual CALCULATE enforce the same increasing-challenge
  domain rule. The C CALCULATE ALL bypass is not retained; rejected challenges
  return 6982 and abort continuation.
- OATH-selected YubiKey serial/HMAC commands run before the OATH access-code gate
  in C. Preserve that binding and delegate HMAC to PASS, without leaking keys.
- SET DEFAULT and record deletion require registry-level PASS/OATH coordination.
  PASS references must not resolve to a new credential after tombstone reuse.
  The repository may reuse physical slots while keeping logical IDs distinct.

The domain service does not allocate a credential list or store all records in
RAM. Its repository enumerates one record at a time, and crypto receives only a
bounded owned credential. Production storage admission must retain the C Flash
reserve policy; the in-memory normal-test repository is not a device backend.

## 6. Complete feature and transport coverage

### Routing matrix

| Entry | C interface owns | Rust adapter and destination | Reply handling |
| --- | --- | --- | --- |
| USB CCID | Slot activation, CCID packets, sequence, Bulk IN/OUT, time extension | APDU adapter -> selected enabled applet | APDU SW/GET RESPONSE in Rust; CCID envelope in C |
| WebUSB | Control transfer setup, framing and endpoint completion | APDU adapter -> selected enabled applet under its transport profile | APDU result in Rust; WebUSB transfer mechanics in C |
| CTAPHID CBOR | HID packet sequencing and bounded message delivery | Native CTAP2 adapter -> FIDO domain | CTAP status and CBOR in Rust; HID packetization in C |
| CTAPHID MSG | HID message framing | U2F APDU adapter -> FIDO/U2F domain, not arbitrary PIV/OpenPGP routing | U2F APDU result wrapped in HID MSG |
| CTAPHID control | INIT/PING packet mechanics and channel identifiers | Runtime validates channel ownership/resynchronization, CANCEL, WINK and any supported LOCK policy | C encodes transport replies/progress; no applet reentry |
| NFC | RF activation/loss, ISO 14443-4 blocks, link chaining, retransmission and WTX | APDU adapter -> selected enabled applet, including NDEF | Rust APDU response; NFC link frames and WTX in C |
| Keyboard HID | Report encoding/transmission/completion | Input event -> runtime -> PASS output job | Bounded output items, not an APDU response |

APDU SELECT state belongs to an APDU application session, not the native CTAP
CBOR route. NFC may carry OATH, PIV, OpenPGP or FIDO APDUs without NDEF being
installed. NDEF file semantics are not part of the NFC driver and may be exposed
over another APDU transport only if that product profile explicitly permits it.

The registry declares enabled protocol bindings and transport admission. USB
interface descriptors, CTAPHID capability flags, CTAP GetInfo, applet AIDs and
algorithm lists must derive from the actual build/backend profile. A selectable
applet need not expose every command over every transport. Never advertise a
feature just because a parser or a stub compiles. Preserve CCID-only zero-applet
builds, PASS-only builds and independently selectable transport features.

### Applet/service responsibility matrix

| Feature | Applet-owned semantics/state | Required shared contracts | Boundary to preserve |
| --- | --- | --- | --- |
| PASS | Slots, configuration authorization, gesture binding, static/HMAC output | Credential verification, atomic slot repository, MAC, keyboard job | No C ADMIN; no OATH dependency for static/HMAC |
| OATH | Record naming/type/digits, challenge authentication, HOTP counters, calculation/list policy, touch requirement | Record store, hash/MAC, presence, stable enumeration and response sources | OTP service returns typed results; PASS cannot access OATH keys or file offsets |
| CTAP2/U2F | RP/user credential model, credential IDs, makeCredential/assertion, attestation, clientPIN/PIN-UV permissions, resident/discoverable credentials, counters and extensions | Bounded CBOR, key/credential repository, RNG/crypto, request-bound presence, cancellation/progress, stable continuation context | Native CBOR and APDU adapters share domain operations, not wire envelopes or a generic global PIN flag |
| PIV | Slots/objects, PIN/PUK, management-key authentication, key PIN/touch policies, GENERAL AUTHENTICATE and attestation | Typed keys, challenge authentication, object streams, crypto, presence, scoped grants | Management-key authorization and PIN authorization remain distinct; reset/import policies stay in PIV |
| OpenPGP | PW1 signature vs other-use validation, PW3, resetting code, PIN policy, data objects, key attributes/import, PSO/INTERNAL AUTHENTICATE and counters | Typed keys, credential mechanisms, TLV/object streams, crypto and presence | Signing authorization consumption, security-environment and multi-command state cannot collapse into PIV policy |
| NDEF | Capability container, selected file, READ/UPDATE BINARY offsets, read-only policy and message publication/NLEN | Object repository, bounded staged writes, APDU parser | NFC framing/WTX does not select files or publish partially written NDEF messages |
| Management | Device identity/configuration, explicit applet enable/reset operations, provisioning and authorized vendor extensions | Version/capability inventory, configuration repository, scoped lifecycle services, platform controls | Optional Rust applet; never required transitively by PASS/OATH or implemented by linking C ADMIN |

Full FIDO migration includes the existing supported credential management,
largeBlobs, authenticator configuration, selection/reset flows, PIN protocols,
attestation and algorithm extensions, not just makeCredential/getAssertion.
Full PIV/OpenPGP migration includes object/certificate streaming, import and
attestation/metadata where currently supported, PIN changes/unblocking, and the
repository's vendor extensions. Build an explicit compatibility inventory from
`include/{ctap,piv,openpgp,oath,ndef,admin}.h`, each C applet and its host clients
before implementing that feature. Presence in an old dispatch switch does not
by itself establish supported behavior; record unsupported commands too.

Device identity/version sources, keymap/configuration storage and manufacturing
state also belong to the full migration inventory. Expose hardware facts through
narrow platform hooks; Rust owns their protocol representation and access policy.
Global reset coordinates enabled applets through typed lifecycle operations and
an explicit recovery/commit plan, never a sequence of C install calls. Persistent
factory state, user credentials and the CIU loader/config page are distinct
reset domains. No applet reset may accidentally overwrite recovery state.

## 7. Transport-independent operations, presence and cancellation

The root runtime is an operation manager, not an APDU dispatcher with special
cases bolted onto it. Conceptual entrypoints carry an ingress profile, owner,
generation and operation ID: begin/feed/end request, deliver event, advance
operation, read response and acknowledge/cancel output. FFI signatures may be
split by input type; a generic C opcode/void-pointer command bus is not required.

Use bounded explicit state machines; no async executor or nested `device_loop`
is needed. Request decoding, waiting and response generation must be separable:

```mermaid
stateDiagram-v2
    [*] --> Receiving
    Receiving --> Running: validated request
    Running --> WaitingPresence: request-bound confirmation
    WaitingPresence --> Running: matching presence event
    Running --> WaitingBackend: asynchronous backend where available
    WaitingBackend --> Running: matching completion
    Running --> Responding: stable result source
    Responding --> Complete: final transfer acknowledged
    Receiving --> Cancelling: reset/error/cancel
    Running --> Cancelling: cancellation boundary
    WaitingPresence --> Cancelling: cancel/timeout/field loss
    WaitingBackend --> Cancelling: cancellation boundary
    Responding --> Cancelling: disconnect/replacement
    Cancelling --> Complete: resources released
    Complete --> [*]
```

Synchronous non-interruptible crypto is permitted as a bounded backend call; the
state diagram does not pretend it can be preempted. Before enabling each long
backend path, establish either cooperative progress points or a C transport-only
keepalive/WTX mechanism that can meet link deadlines during the call. Such a
mechanism uses a prepared small control frame and cannot inspect Rust state,
invoke an applet, reuse the data response buffer, or touch the PKE request source.
Cancellation received during that call is latched for the next safe boundary;
operation acceptance must include measured cancellation/progress latency.

The Rust operation reports Processing or WaitingForPresence. C translates this
into CTAPHID KEEPALIVE, CCID time extension or NFC WTX using that transport's
rules and an explicitly armed lease. These messages keep a link alive, not an
authorization alive. A small C slot-status/control response may proceed while
Rust owns the operation only if it uses separate bounded transport storage and
cannot enter Rust or change operation resources.

A CANCEL affects only the matching owner/channel/generation/operation. A timeout,
USB disconnect, NFC field loss or owner handoff requests cleanup with the same
identity checks; late crypto/HID completions cannot resume a newer session.
Every operation declares irreversible commit points. Cancellation before commit
aborts staged effects; cancellation after a committed counter/key update can
suppress output but cannot promise rollback or reuse a consumed counter. Cleanup
closes leases, aborts uncommitted storage, wipes secrets and releases held keys.

User presence is a request-bound condition separate from PIN/UV verification.
A touch arriving during FIDO confirmation belongs to that confirmation, not to
PASS. A prior or expired touch is not cached indefinitely for a future request.
NFC's current presence behavior is transport-specific: preserve/review it in the
FIDO/PIV/OpenPGP profile, rather than declaring every RF field to be universal
user verification or forcing all NFC requests to wait on an unavailable sensor.

USB interfaces, native CTAPHID channels and NFC compete for one active business
operation and one large scratch reservation. Lightweight channel bookkeeping may
coexist. A foreign request returns protocol-appropriate Busy unless the documented
handoff policy permits cancellation and complete cleanup of the previous owner.
Do not reset the same owner's PIN grants on each transport poll or command;
ordinary PIV/OpenPGP multi-command sessions depend on their specified lifetime.
Conversely, grants and continuations cannot leak from CCID into WebUSB/NFC simply
because all three share an APDU buffer. The profile must define allowed handoffs,
idle leases and applet-specific security-state invalidation explicitly.

CTAP getNextAssertion/credential enumeration, PIV multi-step authentication/SM2
agreement, OpenPGP security state and NDEF updates are application continuations.
They are not ISO input chains or GET RESPONSE pagination. Each has a bounded
typed context, identity binding, allowed next operations and abort rules. A
continuation may retain a session lease across commands without retaining the
original transport bytes. Authentication-token mechanism state with a longer
protocol lifetime is accounted for separately from large operation scratch.

## 8. Shared resources, keys and durable objects

### Memory and input/response sources

Keep one transport I/O domain plus one globally leased applet scratch region,
not separate worst-case buffers for CTAP, PIV and OpenPGP. Size scratch for the
largest justified non-streamable artifact; the current core's design target is
an RSA-4096 result (512 B) plus small wrapping overhead. Any algorithm needing
more must state why, lifetime, alternatives and the complete RAM/stack impact.
Small bounded per-interface packet buffers and protocol metadata are accounted
for explicitly; the shared-scratch rule is not permission for hidden full-message
copies in a C transport or Rust future/operation object.

Represent input as an ephemeral fragment or a typed read-at source lease with
known capacity, stability and close semantics. In both cases consume semantic
fields before the underlying lease ends. A bounded CBOR decoder is structural
like TLV: applets own map schemas, duplicate rules and authenticated byte ranges.
No general CBOR DOM or whole-certificate/key-import buffer is required. Outputs
can compose static segments, small computed fields, leased object ranges and
bounded crypto results; APDU and CTAPHID output adapters use the same source
contract with different framing/status rules.

PKE storage is a volatile staging/crypto resource, never ordinary stable RAM.
A staging lease does not protect bytes from crypto primitives that reuse PKE.
Before PIN-token verification, key generation, signing, keepalive/yield or a
presence wait, fully consume/release the source and retain only the required
bounded semantic state in stable session scratch, or use a justified stable
object source. Never retain PKE offsets for later MAC verification/file writes.

Source completion and transport completion differ. Once bytes have been copied
into a C endpoint-owned buffer, that copy must remain valid through transmission;
source backing may close only after its last required read. Release the operation
lease only when all output/cancellation obligations are complete. Repeated reads
or response retries must not regenerate signatures, increment counters or rerun
a credential operation.

### Keys and algorithm capabilities

Add a typed key service/repository beside opaque object storage. Shared mechanisms
cover key IDs, algorithms/parameters, bounded key material, generation/import
validation, public-key export, signing and agreement/decapsulation as supported.
Applets translate PIV slots, OpenPGP key references and FIDO credential handles
into these types and retain their own usage/PIN/touch/attestation policy. A shared
key type must not make a key usable by another applet without explicit authority.

Rust owns protocol-independent validation/sequencing and durable record codecs;
existing C crypto entrypoints remain backend primitives with their existing
signatures, side-channel constraints and cleanup obligations. Key representations
cross FFI only through reviewed fixed-layout buffers/opaque handles, not native
Rust enums or arbitrary serialized structs. No key service may call a C applet
for import, policy, or authentication. Default key operations never export private
material to a transport; any protocol-authorized import/export path is explicit.

Inventory RSA sizes, supported Weierstrass/Edwards/Montgomery curves, SM2 and
currently supported ML-DSA/ML-KEM operations per applet/backend. Do not advertise
or silently drop an algorithm during migration because the first PASS-oriented
crypto trait only offered hash/MAC. Algorithm availability and key provenance
(e.g. imported vs generated/attestable) are part of the typed result/capability
model. Platform crypto migration/optimization is a separate scope; current CIU
call-path stack limits apply to the Rust caller plus backend together: the ordinary
budget is 5120 B; an exception up to 5632 B needs the documented performance gain
and linker/runtime measurements. Existing measured exceptions do not grant new
wrapper stack space. Do not replicate large keys/polynomials in wrapper frames.

### Object publication and authentication domains

PIV certificates, OpenPGP data objects, NDEF content and CTAP largeBlobs share
bounded object I/O mechanisms, not update/access policy. An applet specifies when
an update is authorized, validated and published; incomplete staged content is
not visible as the current object. A certificate update and a key/metadata update
must state their consistency unit. When several records must change together,
use an explicitly recoverable manifest/journal protocol or a bounded single
record; atomic replacement of one file cannot imply atomic multi-file reset.

Do not write unauthenticated CTAP largeBlob fragments merely to avoid RAM use.
For each authenticated streamed operation, identify exactly which bytes are
needed to check the MAC/token and which storage/crypto calls can destroy their
source. Select a valid consume-then-commit plan or a bounded stable authenticated
fragment design before enabling it. Record limits in the advertised capability
profile instead of expanding shared buffers opportunistically.

Authorization requires distinct mechanism/policy types, including:

| Domain | Required distinctions |
| --- | --- |
| FIDO | PIN vs UV vs UP, token protocol/permissions, RP binding when applicable, expiry/invalidation, retry and temporary-block rules |
| PIV | PIN vs PUK vs management-key proof; per-key PIN/touch policy and single-use/retained authorization |
| OpenPGP | PW1 signing vs other operations, PW3/resetting code, signature-use policy and credential-change invalidation |
| OATH | Challenge-response/access-code state and record-specific presence |
| PASS/management | Configuration/provisioning authority distinct from permission to type or reset another applet |

The common service hosts validated evidence and typed mechanisms. Each domain
specifies creation, scope, consumption and invalidation rules; no shared helper
may weaken those to a universal `verified=true`. Authentication grants, presence
events, transport identity and crypto-key access are separate inputs to policy.

## 9. Representative end-to-end flows used to review the design

These are design walkthroughs, not additional runtime tests in this checkpoint.

1. **CTAPHID makeCredential:** C reassembles/delivers a bounded native message;
   Rust CBOR/schema parsing retains only semantic fields and closes volatile RX
   staging before PIN/UV processing. Runtime binds presence/progress to the CID
   and operation. FIDO invokes key generation, attestation and credential commit
   according to its policy, then supplies a stable CBOR source. C packetizes it;
   matching CANCEL/disconnect takes the documented pre/post-commit path.
2. **PIV key import followed by signing:** APDU chaining feeds the PIV TLV schema;
   management/PIN policy authorizes the operation before protected staging/commit.
   Key material is validated and committed with metadata as a stated consistency
   unit. A later GENERAL AUTHENTICATE uses its own PIN/touch requirement and the
   shared crypto/scratch lease; public output streams without redoing signing.
3. **OpenPGP certificate and PSO:** the selected application's object adapter
   publishes a completed authorized streamed update. Signing verifies the PW1
   signing scope, consumes authorization if its policy requires it and commits
   the signature-counter effect at the defined point. A 61xx continuation reads
   an existing result; it never repeats the private-key operation.
4. **NFC NDEF update then field loss:** C assembles ISO 14443-4 blocks and runs WTX
   timing; Rust routes SELECT FILE/UPDATE BINARY to NDEF. NDEF defines NLEN/message
   publication and read-only policy. Field loss invalidates the operation, closes
   reads and aborts unpublished content without formatting storage or inheriting
   grants from an earlier USB session.
5. **USB/NFC competition during FIDO presence:** an NFC activation while CTAPHID
   owns a waiting operation cannot run another applet in the same scratch. Busy
   or an explicit cancellation/handoff occurs first. A touch completes only the
   currently bound request; no PASS keystroke or stale assertion is emitted.
6. **PASS HOTP output:** PASS resolves a stable OATH credential ID through a typed
   service, obtains a durably reserved OTP and starts a bounded keyboard job.
   Disconnect wipes the job; reconnect does not resend it or undo the counter.
7. **Management reset:** Rust verifies reset-specific authority and obtains an
   exclusive lifecycle lease, cancels active streams/output, then executes the
   declared recoverable reset plan for enabled applets. Shared credential changes
   invalidate dependent grants; loader/config recovery bytes stay outside that
   reset domain. Partial commit is surfaced as recovery-required, not success.

## 10. Current implementation and remaining changes

| Current location | Required direction (implemented incrementally) |
| --- | --- |
| `core/src/runtime/engine.rs`, `registry.rs` | Implemented APDU ownership/chains/response routing; native CTAP and asynchronous operations remain future work |
| `core/src/applets/admin/protocol.rs`, `pass_config.rs` | ADMIN owns PIN and PASS management commands; remaining C ADMIN commands are tracked in the checkpoint |
| `core/src/applets/pass/` | Typed slot service and explicit codec; no APDU/SW or OATH stub |
| `core/src/applets/admin/pin.rs` | Typed C-compatible PIN mechanism; no KDF; grants held by runtime |
| `core/src/ports/`, `ffi/src/` | Typed storage/crypto contracts and separate unsafe C ABI; add capabilities only for real operations |
| `core/src/applets/pass/output.rs`, C keyboard transport | Rust owns gesture/job/secret text; C maps and transmits one character; physical typing still needs an end-to-end normal check |
| CIU storage backend | Mount without autoformat; /rust namespace; atomic replacement; word-aligned file cache |
| `core/src/applets/oath/` | Typed credentials/codec, repository contract, naming, HOTP/TOTP and access-code services implemented; five normal domain tests pass. Adapter, concrete storage, USB, presence and PASS binding are integrated; see oath.md for measured validation |
| CTAP/PIV/OpenPGP/NFC/NDEF | Architecture specified; not enabled or implemented by this profile |

The management AID and existing command numbers are compatibility requirements.
ADMIN owns the PASS configuration schema. The existing OATH-selected YubiKey
HMAC commands must delegate to the PASS service; do not invent a replacement
wire binding. SELECT/routing remains common runtime behavior.

### OATH implementation details

`core/src/applets/oath/repository.rs` binds typed OATH repositories/MAC to the narrow platform
capabilities. It scans one 146-byte record at a time; no credential-count-sized
RAM table exists. Stable IDs are distinct from file slots and tombstones.
`core/src/applets/oath/protocol.rs` owns only wire parsing, status mapping, bounded command
bytes, a 256-byte reply page, authentication session and enumeration cursor.
Common APDU/chaining and byte-TLV primitives remain in `protocol/`.

`core/src/runtime/presence.rs` owns a request-bound 30-second press/release wait. Its C
progress callback only maintains CCID link timing and reports cancellation;
it must not reenter Rust. A runtime presence request claims its gesture before
waiting; success, timeout and cancellation all suppress PASS until release. This synchronous operation is sufficient
for this CCID profile; it does not implement the future multi-transport
cooperative-operation scheduler described elsewhere in this design.

Core/FFI `admin`, `pass`, `oath` and `openpgp` features are independent.
Device/host OATH profiles explicitly combine `admin`, `pass` and `oath`;
OATH bindings are available only when PASS is also enabled. Zero and ADMIN +
PASS remain independent builds. No OATH-only
device profile is advertised. The OpenPGP profile adds raw asymmetric crypto and staged-object transactions;
C otherwise remains storage and transport mechanics.

## 11. Design decisions and remaining specifications

Decided by this proposal: ownership/dependency direction, main-loop serialization,
explicit applet assembly, distinct native CTAP/APDU routing, one large-resource
owner, cooperative operation lifecycle, transport-only link maintenance,
streamed input/output, scoped mechanism-specific grants, typed key services and
backend failures, explicit provisioning, and separate new record namespaces.
The zero-applet USB target remains independently buildable.

The following must be resolved in small follow-up specifications before their
corresponding device functionality is enabled:

| Specification | Recommended direction | Required outcome |
| --- | --- | --- |
| PASS wire/API profile | Preserve C ADMIN configuration and OATH-selected YubiKey HMAC binding | Complete command coverage and host-client compatibility |
| Credential/provisioning | Versioned PIN bytes/counters; C-compatible default PIN | Record bytes and C-compatible change/unblock/reset lifecycle |
| Storage backend | Dedicated namespace on existing LittleFS without autoformat | Atomic-replace durability and uncertain-error handling, mount and provisioning paths |
| Existing credential compatibility | No implicit migration | Choose fresh provisioning or an explicit authenticated migration path before touching legacy records |
| Keyboard profile | Bounded output job and report transport | Initial layout/character set, gesture/slot policy, release/cancellation behavior |
| Full compatibility inventory | Track every current command/extension and advertised capability | Existing behavior, intended Rust behavior, intentional differences and validation status per feature |
| FIDO profile | Shared CTAP/U2F domain with native/APDU adapters | Supported version/commands/extensions/algorithms, CBOR limits, token scopes, UP/UV, continuation and cancellation rules |
| PIV/OpenPGP profiles | Common keys/objects, separate policies | Command/algorithm mapping, PIN/management roles, key import/provenance, touch and grant-consumption rules |
| NFC/NDEF profiles | Separate transport and application | Field/WTX deadlines, USB handoff, presence semantics, file selection and atomic message publication |
| Runtime/control ABI | Owner/channel/generation/operation-bound events | Progress/abort/transfer-completion contracts, long-backend latency and no-reentry proof |
| Memory/key services | One leased scratch; volatile PKE staging; typed keys | Per-operation retained bytes, clobber boundaries, stack budgets and crypto capabilities |
| Management/migration/reset | Explicit optional management and recoverable lifecycle changes | Applet config/identity, factory/user/loader separation, import/reset commit and recovery plan |

These are product/security/compatibility decisions, not hidden defaults to fill
in while writing FFI code. Implemented storage/PIN behavior is recorded above;
full ADMIN/PASS compatibility and physical keyboard testing are still incomplete.

## 12. Implementation order

The ADMIN + PASS + OATH checkpoint exists. Foundation steps 1-4 below are now
implemented: workspace/ownership consolidation, production frame consumption,
one response cursor, and normal long-command fixtures. Existing host/device
regression results are recorded in the refactor checkpoint below. Actual
PIV/OpenPGP consumers, future shared key scratch sizing and multi-transport
presence scheduling remain subsequent applet milestones.

1. Consolidate the workspace and applet-local modules from section 2. Separate
   safe core from FFI, narrow platform ports and move cross-applet business out
   of registry/engine. Preserve current wire behavior and persistent formats.
2. Establish one selection owner, one exchange lifecycle and one response cursor.
   Keep a real pull/close response-source contract, including generated output;
   remove duplicate implementations only after their replacement is exercised.
   Define scratch/staging leases, transfer completion and explicit abort cleanup.
3. Connect the common input path to production ADMIN/OATH consumers. Separate
   frame completion from logical command completion; retain bounded collectors
   for small requests, incremental TLV sinks and source-backed input. The C
   interface may still deliver a complete short frame as one chunk. Do not wait
   for a whole chained command or enlarge its buffer before dispatching it.
4. Before declaring this foundation ready, run normal host scenarios through the
   actual runtime with test-only long-command consumers: a valid multi-APDU key
   template, streamed message hashing, a large object write/read and generated
   multi-chunk output. Verify exact results, retained memory and close/commit
   counts. These fixtures do not enable a fake PIV applet in device firmware.
   Repeat existing ADMIN/PASS/OATH normal host and USB workflows. No fuzz,
   malformed-input sweep or fault-injection campaign is implied.
5. Introduce PIV or OpenPGP as an explicit next feature slice with real key/object
   services and algorithm-specific import/signing consumers. Carry forward the
   section 14 streaming inventory; do not claim full support from small-command
   tests alone. Close remaining ADMIN/PASS compatibility entries separately.
6. Add FIDO with native CTAPHID routing, bounded CBOR/source readers and progress/
   cancellation. Preserve the bounded standalone CCID FIDO extended-input path
   when that profile is enabled; it is not general extended APDU support.
7. Add NFC transport/NDEF and combined-profile validation in their scheduled
   checkpoints. NFCC remains deferred; applets remain individually opt-in.

At each stage record feature set, linked-source/symbol inventory, protocol
compatibility, persistent format version, Flash/static RAM, retained scratch,
stack and relevant latency. Retain the zero-applet target as the baseline and
keep each new applet opt-in. Shared services grow only when a concrete operation
needs them, while the contracts are reviewed against the full matrix above.

Each implementation checkpoint uses normal functional tests and build/link
checks. Device writes remain subject to the vector/ResumeLoader gate; no boundary,
differential or fuzz campaign is required by this migration plan.
Every hardware image still passes the 48-vector/ResumeLoader
boot gate; NFCC remains deferred. Measure each stage's Flash/static RAM and any
affected stack path without interpreting different functionality as a Rust saving.

## 13. Source anchors for implementation specifications

These sources document the existing behavior to inventory, not implementation
dependencies to copy into the Rust target:

- [Core repository constraints](../../AGENTS.md): shared scratch, PKE clobber
  boundaries, streaming, session cleanup and protocol-specific caveats.
- [Applet assembly](../../src/applets.c) and
  [current device orchestration](../../src/device.c): implicit installation and
  shared lifecycle responsibilities that the explicit Rust registry replaces.
- [CTAPHID](../../interfaces/USB/class/ctaphid/ctaphid.c),
  [CCID](../../interfaces/USB/class/ccid/ccid.c) and
  [NFC](../../interfaces/NFC/nfc.c): current routes, control/progress handling and
  transport teardown. Their applet calls are not part of the retained C boundary.
- [Existing PIN mechanism](../../src/pin.c),
  [PIV commands](../../include/piv.h),
  [OpenPGP commands](../../include/openpgp.h) and
  [management commands](../../include/admin.h): compatibility and role inventory.
- [NDEF implementation](../../applets/ndef/ndef.c): selected-file and update
  semantics that must remain separate from the NFC link implementation.
- [Current Rust prototype](../core/src/runtime/engine.rs): concrete refactoring starting
  point, not the final full-core runtime contract.


## Protocol authority after review

For implemented ADMIN commands, the published CanoKey ADMIN protocol is the
wire contract. CLA 10 is not a generic ADMIN extension; unknown instructions
return 6D00 and reserved fields are checked strictly. See admin-pass.md for
same-AID selection, missing Le, factory reset, output leases and explicitly
retained extensions. Do not restore C parser permissiveness merely to match
malformed-command behavior. The confirmed current OATH A1/A2/A5 and access-code
profile is authoritative; the historical public page is not a migration target.
See oath.md for session reselection, page cancellation, strict A5 fields and
shared increasing-challenge policy. SELECT version bytes are generated from
the same explicit release configuration as the C build.


## 14. Streaming review and mandatory refactoring constraints (2026-09-23)

This section refines sections 4, 8 and 12 after inspecting the C implementation.
Simplification means fewer owners and duplicate mechanisms, not replacing
streaming with full-message buffers. Before refactoring, Rust `FrameDecoder` and TLV `Decoder` were exercised only
by protocol tests while firmware used full-frame `parse`. The refactor now uses
`FrameDecoder` in production and runs long consumers through that same runtime.
ADMIN/OATH deliberately remain bounded small-command collectors; PIV/OpenPGP
wire consumers and real cryptographic imports are not implemented by this work.

### Observed C paths to preserve as capabilities

| Path and source | Actual behavior | Rust requirement |
| --- | --- | --- |
| `src/apdu.c::process_apdu_from`, `apdu_process_streaming_message` | Selected PIV/OpenPGP receive individual APDUs before generic whole-command reassembly | Dispatch body fragments to an active command consumer; a logical command need not fit the short-frame buffer |
| `applets/piv/piv.c::piv_import_asymmetric_key`, `src/key.c::ck_parse_piv_stream_update` | TLV state survives APDUs; RSA components are filled directly in typed key material; final validation precedes key replacement | Incremental key-template parsing, bounded semantic key state, final validation/publication; no second full wire-template buffer |
| `src/key.c::ck_parse_openpgp_stream_update`, `applets/openpgp/openpgp.c` import path | Template/component lengths and key bytes are processed incrementally across APDUs | Shared TLV primitives with a distinct OpenPGP schema/consumer, not one universal PIV/OpenPGP parser |
| `piv.c::piv_ga_stream_update`, `piv_general_authenticate_stream` | Nested 7C lengths persist across chunks; ML-DSA, SM2 full-message and randomized Ed25519 modes update crypto state while consuming message bytes | Support incremental crypto during receive, followed by algorithm-specific finalization; do not buffer the message or silently substitute a different signing mode |
| `piv.c::piv_put_data` | Authorized first chunk writes the object, later chunks append with capacity accounting | An authorized object sink with an explicit publication/abort policy; no whole-certificate buffer |
| `piv.c::piv_get_large_data`, `piv_get_data_response` | File bytes are read per GET RESPONSE using an applet-local offset | Preserve bounded file reads, unify offset/lifecycle ownership in the runtime |
| `piv.c::piv_7c_stream_source_read`, ML-DSA response code; OpenPGP response sources | Headers, file/memory ranges and generated crypto output are emitted on demand with close callbacks | Composable streaming sources and resource release, without allocating a complete signature/certificate/public-key encoding |
| `src/apdu.c::fido_apdu_input` and CCID FIDO extended-input path | Large CBOR can be source-backed in PKE; this is staging, not the PIV TLV push path | Retain both push consumers and bounded pull input sources, with explicit PKE clobber lifetimes |

C remains evidence for capability and lifetime requirements, not authority over
new protocol rules. In particular, C PUT DATA writes incrementally to the target;
it is not an atomic staged replacement. A Rust staged publish/abort policy must
be specified as such, including disk space, interruption and durability behavior,
not described as existing C behavior. Filesystem staging is appropriate for an
authorized persistent object update, never a generic substitute for RX RAM.

### Three independent input boundaries

1. Transport fragments form one APDU envelope. A common decoder identifies the
   header/body/Le; transport lengths and envelope errors remain frame-level.
2. ISO CLA chaining joins APDU bodies into one logical command. Each APDU still
   gets its own response/acknowledgement. An intermediate APDU end does not call
   the command's final validation or publish a key. Match owner and command
   identity, enforce the command-specific total limit and abort on replacement.
3. TLV boundaries are independent of both. A tag, multi-byte length or value may
   continue in the next input chunk/APDU. Structural state tracks bounded tag/
   length progress and container budgets; the applet tracks legal tags/order,
   component destinations and required fields. No DOM or recursive allocation.

The conceptual consumer lifecycle is `begin -> feed* -> end_frame` for each
frame, then `finish_command` on the final frame, or `abort` on termination.
Concrete APIs may combine calls, but must preserve these distinct events.
Small commands use bounded collectors; key import uses a component sink; streamed
signing uses a crypto sink; object update uses an authorized storage sink.
A pull input source feeds the same semantic consumers through a small window.
One envelope implementation serves complete-frame and fragment entrypoints;
this does not require every algorithm to have the same consumption strategy.

`finish_command` is not necessarily the first crypto call: hash/signing-stream
initialization and updates may run during `feed`. Final success/publication waits
for complete syntax, declared lengths and domain validation. Authentication and
irreversible effects follow the command's explicit policy, not a universal
"buffer everything, then authenticate" rule. Final Le may arrive only at frame
end; it must not prevent early body consumption or leak into applet domain types.

### Resource lifetime and output contracts

- Keep one session owner and shared transient workspace across applets. Typed key
  material, hash state and irreducible results still consume real memory; list
  their sizes and overlapping lifetimes. A 512-byte result target is not a claim
  that every RSA import or crypto call fits in 512 bytes.
- C PIV import stores partial key material in PKE between APDUs and restores it
  into RAM before final validation. Preserve incremental import, but do not copy
  this storage choice without proving its lifetime. A software lease cannot
  prevent crypto/keepalive from overwriting hardware scratch. Prefer stable
  shared semantic state; document any constrained PKE use and its clobber proof.
- Incremental crypto sinks can themselves use PKE. A PKE-backed input window
  therefore must be fully consumed or moved to justified stable state before
  such a call. The input source and crypto workspace cannot be assumed disjoint.
- One runtime response cursor governs Le, 61xx and GET RESPONSE. Sources may be
  memory/object ranges, segment compositions or sequential generators. Do not
  demand arbitrary replay from a stateful generator: request monotonic chunks
  and keep the current transport chunk stable for retransmission. Never rerun
  signing, randomness or counter commits for GET RESPONSE/retries.
- Cleanup covers successful drain, replacement, reset, cancellation and failure;
  close/abort release sources, staging, crypto state and secrets once. If backend
  access is required, use explicit runtime cleanup; `Drop` alone is not a storage
  transaction or asynchronous cleanup mechanism.
- The unsent response must survive incoming GET RESPONSE and C's SW trailer
  writes. Use stable non-overlapping backing or an explicitly verified bounded
  overlap scheme; Rust slice types alone do not prove external C writes safe.
- Do not remove response-source capability because the existing Rust `Response`
  wrapper is unused. Replace duplicate wrappers with one exercised contract.
  OATH A5 pagination remains separate from ISO response delivery.

### Acceptance and scope

The next refactor preserves the currently enabled zero/ADMIN+PASS/OATH profiles,
protocol-authoritative behavior and stored record formats. Long-command normal
fixtures must exceed the existing short-command buffer and pass through the real
chain/consumer/response lifecycle; include a valid TLV length split across chunks
as an ordinary fragmented transfer, not an exhaustive boundary campaign. Record
RAM versus payload length, scratch/stack requirements and backend commit/close
counts. Actual PIV/OpenPGP device support remains a later opt-in milestone with
its own real key/crypto/object checks. No unimplemented capability is advertised.

Do not enlarge the APDU buffer, remove an existing algorithm, introduce heap
allocation or use flash as generic RX scratch to make the refactor shorter.
C interfaces remain minimal; no CIU/startup changes are planned here. Future
firmware changes retain the vector address, all 48 ordered/reserved mappings
and startup ResumeLoader invocation, with the existing boot gate before flashing.


### Foundation implementation checkpoint (2026-09-23)

- One workspace with protocol/core/ffi; applet domain/protocol/repository files
  are co-located. Core forbids unsafe code. FFI retains the same C ABI.
- Runtime has no duplicate selected flag or ADMIN opcode dispatch. Registry owns
  selection/grants and delegates typed reset/HOTP workflows. Response cursor owns
  no borrowed reference into the runtime; sources close explicitly with backend
  access. Push and pull input share the production frame/command lifecycle.
- Storage/crypto/device/erasure ports are disjoint; OATH RefCell is removed.
  OATH executes from its bounded request without a second full request copy.
  A repository-local ID/slot cache avoids repeated prefix scans during ordinary
  enumeration without adding a credential-count-sized RAM index.
- Host fixtures cover a 1,300-byte component template (structural parsing, not
  real RSA import), 8 KiB SHA-256, 16 KiB object publication/readback and 4 KiB
  sequential output. Exactly one finalization/commit and source closure are
  checked. Host mock storage is not firmware scratch; no persistent format,
  PIN policy or applet algorithm changed.
- Small ADMIN/OATH collectors remain intentional. Future PIV/OpenPGP command
  schemas, algorithm-specific consumers, hardware scratch sizes and incremental
  crypto clobber proofs still need their real implementation/measurements.
  Presence remains synchronous for CCID. These are not advertised new features.

Validation of this foundation checkpoint: all three host profiles and firmware
boot gates passed; 3 protocol tests, 5 OATH domain tests and 4 runtime streaming
scenarios passed. The device passed 76 OATH, 19 ADMIN/PASS and 29 restart/
power-cycle checks. Physical touch and keyboard capture were not repeated.
Current OATH image: 49300 B Flash, 4148 B static RAM, 7680 B reserved (not measured)
stack, an increase of 1404/56 B over the preceding OATH review image. New firmware
remains installed. Evidence: CIU `hil-reports/rust-core-refactor-20260923/README.md`.


## 15. OpenPGP implementation checkpoint (2026-09-23)

This checkpoint supersedes the earlier foundation-only statements about future
OpenPGP support; they describe that earlier milestone, not the enabled profile.
PIV/CTAP/NDEF/NFC remain scheduled separately. The complete OpenPGP command,
algorithm, persistence and validation contract is [openpgp.md](openpgp.md).

- OpenPGP domain/adapter/repository code is co-located under `applets/openpgp`.
  `protocol.rs` handles lifecycle/PIN routing; `data.rs` owns DO schema;
  `key_commands.rs` handles key-command wire formats, while `service.rs` owns
  session authorization, PIN changes and key-operation policy without APDU/SW. Generic APDU/TLV and the
  sole response cursor remain shared. No old C applet or `src/key.c` is linked.
- Registry owns a single 2332-byte semantic workspace, not an OpenPGP static.
  RSA ABI material and ECC signing scratch share it. This is the shared-resource
  contract that later PIV/CTAP consumers must use, not a license to add one
  worst-case workspace per applet. Only explicit byte components are persisted.
- Certificates use authorized staged-object append/atomic publish and ranged
  reads. Key descriptors stream directly into components. Existing small
  ADMIN/OATH collectors remain intentional; the common APDU buffer is unchanged.
- Key/counter atomicity, grant lifecycle, UIF policy, default PINs and all nine
  existing OpenPGP algorithms are implemented. ADMIN 03 and the factory-reset
  flow compose the OpenPGP reset operation.
- Function boundaries separate APDU decode and unrelated applet temporaries
  from native crypto frames. The optional primitive workspace variants reuse
  caller-owned memory with the same arithmetic and old public entrypoints.
  Measured normal OpenPGP stack high-water is 5072/5120 bytes; reservation remains
  7680 bytes. Physical touch was deferred; NFC semantics remain unimplemented.
- The C CCID timer maintains time extensions during blocking RSA generation,
  without Rust reentry or PKE access. USB reset invalidates the transfer and
  triggers main-loop session cleanup. Startup/vector/ResumeLoader gates remain
  mandatory before producing the HEX file.

Final device footprint and evidence are recorded in CIU
`firmware/rust-core/README.md` and `hil-reports/rust-openpgp-20260923/README.md`.

## 16. Design review corrections (2026-09-23)

These contracts supersede the earlier feature coupling and cross-applet reset
implementation details:

- Dependency direction is registry -> flows -> applet services/repositories.
  Applets never call flows. PASS output receives a registry resolver and only
  owns gesture/output lifetime. Flows return domain errors, not status words;
  registry/protocol adapters translate them at the response boundary.
- Factory reset verifies strong presence and revokes sessions in registry, then
  invokes persistent service operations with ADMIN PIN last. No flow accepts
  an OATH/OpenPGP protocol adapter. OATH deletion still removes PASS bindings
  before deleting a credential, preserving stable-ID safety.
- PASS writes borrow storage and erasure only; presence waits borrow device
  only. OATH repositories keep their backend fields private, with scoped borrows
  instead of rebuilding Platform inside an applet. A5 paging lives under its
  protocol adapter; generic APDU/GET RESPONSE state stays in runtime.
- OpenPGP PIN/repository services return typed errors. Its session service owns
  key-generation/use policy and grant transitions; adapters own APDU parameters,
  TLV schema and status words. The session workspace is borrowed, never copied.
- Crypto operation names explicitly select RSA PKCS#1 v1.5 signing/deciphering,
  EC signing or key agreement. Future raw RSA users require an explicit operation;
  they must not silently inherit OpenPGP padding. Native ABI key views remain
  justified by stack limits and are never persisted as native structs.
- One Registry/Router implementation covers all feature combinations, including
  zero applets. Disabled applets have no state or installation side effects.
  The four Cargo features are independent; device presets choose compositions.
- Runtime presence Request marks an attempt before calling the device wait.
  Keyboard output consumes that marker and suppresses a held contact through
  release on every outcome. Reset/factory recovery also inhibit stale gestures.

Keep bounded ADMIN/OATH collectors, streamed key/certificate input and one shared
crypto workspace. Do not add a dynamic applet registry, heap allocation, per-applet
large buffers or generic whole-message staging to simplify these boundaries.
Resource and device-validation results for this correction are recorded in CIU
`hil-reports/rust-design-review-20260923/README.md`.
