## The design of canokey-core

A platform-independent security-key core for constrained microcontrollers.

canokey-core implements several security-key applications in one firmware
core: FIDO2/U2F, OpenPGP, PIV, OATH, NDEF, PASS, and the administrative
interface. It is not a board support package. Hardware-specific behavior such
as clocks, timers, randomness, flash layout, touch sensing, NFC signaling, and
optional crypto acceleration belongs to the platform port.

The core exists in the middle of two very different worlds. On one side are
host protocols that can carry large CBOR objects, APDU templates, public keys,
certificates, and credential lists. On the other side are firmware targets with
small RAM, bounded stack, no heap, and sometimes crypto hardware that reuses
the same memory used for staging input.

The main design pressure is not the number of supported applets. It is keeping
many protocol personalities sharing the same constrained resources without
letting a command accidentally depend on transport buffers, PKE staging memory,
or scratch space whose lifetime has already ended.

canokey-core therefore prefers explicit ownership, shared scratch, and
streaming over per-protocol buffering. Large protocol data is consumed or
emitted in bounded pieces. State that must survive a long-running command is
reduced to semantic command state, not kept as a pointer into the original
transport input.

## The problem

Security-key commands often look small at the command-dispatch layer, but the
objects they carry are not always small enough to fit in one firmware buffer.
OpenPGP and PIV can move RSA key material, certificates, and public key
encodings. FIDO2/CTAP uses CBOR objects that may exceed the inline HID buffer.
Credential-management and large-blob flows may need to parse or emit structured
objects larger than a short APDU payload.

The transport model adds another constraint. CCID, WebUSB, and NFC enter the
core through APDU processing. CTAPHID has its own HID framing, but still reaches
the same CTAP applet semantics. The applet should not need a different command
implementation just because the bytes arrived over HID instead of APDU.

Responses have the same shape as requests. A public key, certificate, wrapped
PIV object, OpenPGP object, or credential list may be too large to build in the
short response buffer. A design that requires every response to be materialized
before the first byte is sent would either waste RAM or impose artificial
protocol limits.

Crypto also changes the lifetime rules. Key generation, signing, PIN/UV-token
verification, RSA, ECC, ML-DSA, and platform PKE helpers may reuse large
temporary memory. On some ports, the logical PKE buffer maps to hardware PKE
registers. It is useful staging space, but it is not stable storage for command
bytes that must survive later crypto operations.

User presence introduces long pauses in the middle of a command. A CTAP command
may parse input, send keepalive frames, wait for touch, then continue with
crypto and storage. During that wait the main loop can run and shared resources
can be reused. If the command still needs raw request bytes after the wait,
those bytes must have been consumed or copied into stable state first.

These constraints lead to a few requirements:

1. RAM and stack usage must stay bounded.
2. Large protocol data must be streamable.
3. Transport buffers must not become applet state.
4. Shared temporary memory needs explicit ownership.
5. Data that survives crypto, keepalive, touch waits, main-loop re-entry, or
   session yields must live in stable semantic state.

## canokey-core

canokey-core separates transport framing from applet semantics and uses shared,
explicitly owned memory for the bounded parts of command execution.

```
USB / NFC event
     |
     v
transport framing
CTAPHID / CCID / WebUSB / NFC
     |
     v
protocol dispatch
CTAP HID / CTAP APDU / ISO APDU
     |
     v
applet handler
CTAP / OpenPGP / PIV / OATH / NDEF / PASS / admin
     |
     +--> direct response in a short buffer
     |
     '--> streaming response source
```

Transports receive frames, assemble the protocol unit they are responsible for,
and send response chunks. CTAPHID may receive a CBOR message inline or use
staging for a larger message. CCID, WebUSB, and NFC enter through APDU
processing. These paths differ at the framing layer, but applet handlers should
operate on parsed protocol meaning rather than transport mechanics.

APDU processing uses short buffers plus ISO command and response chaining.
Command chaining lets the host send multi-block input without requiring
extended-length APDUs. Response chaining lets the device return large output
through `GET RESPONSE`. Chaining is the protocol mechanism for multi-block
data; it is not a reason to increase `APDU_BUFFER_SIZE`.

`shared_io_buffer` is the short-lived transaction buffer for APDU-sized work.
It is protected by explicit acquire and release ownership. It must not be held
across re-entry points such as `device_loop()`, because another enabled
transport may need the same shared buffer.

`device_applet_session_acquire()` is the cross-applet exclusivity boundary for
long-running or multi-step applet work. It prevents applets from assuming they
can all own large transient state at the same time. This is what makes a global
applet-session scratch area practical: the firmware reserves memory for the
largest live non-streamable artifact, not for the sum of every applet's worst
case.

The applet-session scratch area is for bounded state that must survive within a
session and cannot be streamed further. It is not a license to materialize whole
requests or responses. The intended use is durable command state, small
wrappers, and unavoidable crypto or encoding fragments.

The PKE buffer is staging. A handler may read PKE-backed input while it is
still parsing or immediately consuming the staged bytes. It must stop treating
that storage as valid before any operation that may use crypto, send keepalive,
wait for touch, yield the applet session, or call back into the main loop.

Large responses use pull-based response sources instead of full materialization:

```c
apdu_response_source_set(total_len, sw, read, close, ctx);
```

The APDU layer asks the source for chunks as the host sends `GET RESPONSE`.
The source may stream from prepared memory, files, generated segments, or other
bounded backing state. The `close` callback releases any resource when the
stream finishes or is preempted.

## Flash capacity

Persistent storage capacity is a platform property, not a core constant.
canokey-core mounts LittleFS through the `lfs_config` supplied by the platform
port. The total usable filesystem size comes from `block_size * block_count`,
so a port can change the flash partition by changing its LittleFS geometry
without changing applet protocol code.

The core still needs to expose and reason about that capacity. `get_fs_size()`
reports the mounted filesystem size in KiB, and `get_fs_usage()` reports the
current LittleFS block usage in KiB. The admin applet's flash-usage command
returns those two values to host tooling, so the reported capacity follows the
mounted filesystem instead of a build-time product constant.

Free-space checks use the same runtime geometry. `get_fs_free_bytes()`
estimates remaining space from LittleFS's used block count and the configured
block size. `fs_has_free_space(write_bytes, reserve_bytes)` is the admission
control helper used before writes that extend storage. It subtracts the reserve
before comparing against the requested write so oversized requests cannot wrap
around and appear valid.

This check is deliberately conservative. LittleFS uses copy-on-write metadata
and may need extra blocks for a write, so an estimate cannot prove that a later
write will succeed. Applets must still handle `LFS_ERR_NOSPC` from the actual
write path and map it to the protocol-visible storage-full status.

Capacity-sensitive applets should distinguish overwriting existing records from
extending files. Reusing a tombstoned resident credential or OATH slot does not
consume new file capacity in the same way as appending a new record. CTAP and
OATH therefore run admission control only for the append case, while normal
write errors remain authoritative.

Applets also keep explicit reserve space for LittleFS metadata and future
maintenance writes. CTAP reserves `CTAP_FS_RESERVE_BYTES`; OATH reserves
`OATH_FS_RESERVE_BYTES`. These reserves are part of the flash-capacity design:
larger flash partitions automatically allow more records, but no applet should
drive the filesystem all the way to zero free blocks just because the raw
capacity calculation says another payload might fit.

Host-visible capacity should be derived from the same storage model. CTAP's
remaining resident-credential count combines reusable tombstones with a
conservative estimate of how many brand-new credential records fit in the
remaining flash after reserve. It is a hint for clients, not a promise that
every later write will succeed.

Changing flash capacity therefore has one rule: adjust the platform LittleFS
geometry and let core derive totals, free-space admission, and host-visible
capacity from the mounted filesystem. Do not add independent per-applet
capacity constants unless the protocol object itself has a fixed maximum size
or the applet needs an explicit reserve for filesystem health.

## Request lifetimes

Request bytes are input, not command state.

A command handler may parse request bytes from inline transport memory, shared
APDU storage, PKE-backed staging, or another bounded source. After parsing, the
handler keeps only the semantic information it needs: flags, hashes, key
parameters, credential IDs, file offsets, policy values, or bounded byte
strings that were deliberately copied.

A safe source-backed command lifecycle is:

```
create request source
        |
        v
parse required fields
        |
        v
copy semantic state
        |
        v
clear request source
        |
        v
keepalive / user presence / crypto / storage / response
```

This rule exists because request sources may point into storage whose lifetime
is shorter than the command. CTAPHID channel memory, APDU aggregation buffers,
PKE staging, and transport state can be reused by later transport progress,
APDU output, crypto helpers, PKE operations, or applet-session transitions.

The main unsafe boundaries are keepalive, `WAIT()`, user-presence waits,
`device_loop()`, applet-session yield or release, PIN/UV-token verification,
key generation, signing, ML-DSA streaming, file/key helpers that may call
crypto, and response generation that may reuse shared buffers.

There are three safe patterns for request data.

The first is to parse and copy semantic state. Use this for normal command
fields such as options, flags, hashes, algorithm identifiers, credential IDs,
PIN policy, touch policy, and key metadata. The copied state should describe
what the command means, not preserve the whole request encoding.

The second is to consume bytes while the source is valid. Use this when raw
bytes are needed only to compute or verify something: hash a payload as it is
read, verify an auth parameter before crossing an unsafe boundary, or parse a
TLV stream directly into key storage and metadata.

The third is to materialize a bounded fragment. Use this only when the exact
bytes are required later and the bound is known to fit stable scratch. The code
should make the limit obvious and document why the fragment cannot be streamed,
hashed, parsed, or recomputed before the unsafe boundary.

For output, the equivalent rule is to stream large responses. If a response
does not fit the short APDU buffer, register a response source rather than
building the whole object in RAM.

Never keep an offset, pointer, or parser state into transport or PKE-backed
request storage after an unsafe boundary. If bytes must survive, they must be
copied into bounded stable state, written as legitimate persistent protocol
state, or consumed before the boundary.
