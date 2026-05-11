# AGENTS.md — canokey-core Codebase Guide

> Quick-reference for AI agents and contributors working on this repository.

---

## Project Overview

`canokey-core` is a platform-independent C11 library implementing an open-source security key. It supports:

- **FIDO2 / U2F** (CTAP2/CTAP1, Ed25519, HMAC-secret, ML-DSA-65)
- **OpenPGP Card V3.4** (RSA 2048/3072/4096, ECDSA, Ed25519, X25519)
- **PIV** (NIST SP 800-73-4, with RSA 3072/4096, Ed25519, X25519)
- **HOTP / TOTP** (OATH)
- **NDEF** (NFC tag emulation, requires NFC hardware)
- **WebUSB web interface** (browser-based configuration)
- **KBDHID / PASS** (keyboard output of OTP codes, requires touch sensor)

The library is meant to be linked by a platform port (e.g. `canokey-ciu`, `canokey-stm32`). It does **not** contain any hardware-specific code by itself.

---

## Repository Layout

```
canokey-core/
├── include/            # Public headers (device.h, apdu.h, key.h, …)
├── src/                # Platform-independent core (device.c, apdu.c, key.c, …)
├── applets/            # Per-applet implementations
│   ├── admin/          # Admin applet (config, WebUSB control)
│   ├── ctap/           # FIDO2 / CTAP2 applet
│   ├── ndef/           # NDEF / NFC tag applet
│   ├── oath/           # HOTP/TOTP applet
│   ├── openpgp/        # OpenPGP Card applet
│   ├── pass/           # KBDHID password output applet
│   └── piv/            # PIV applet
├── interfaces/
│   ├── USB/
│   │   ├── core/       # USB stack (usbd_core, usbd_ctlreq, …)
│   │   ├── device/     # USB device descriptors and canokey composite device
│   │   └── class/
│   │       ├── ctaphid/    # CTAPHID HID class driver
│   │       ├── ccid/       # CCID smart-card class driver
│   │       ├── kbdhid/     # Keyboard HID class driver
│   │       └── webusb/     # WebUSB vendor interface
│   └── NFC/            # NFC interface (FM11NC / FM11NT)
├── canokey-crypto/     # Submodule: crypto primitives (ECC, RSA, AES, SHA, …)
├── littlefs/           # Submodule: embedded filesystem
├── tinycbor/           # Submodule: CBOR encoder/decoder
├── virt-card/          # Virtual card for host-side unit/integration tests
├── test/               # CMocka unit tests
├── fuzzer/             # honggfuzz fuzzing harness
└── scripts/            # Code-generation scripts (gen_ctap_get_info.py)
```

`fido2-tests/` is referenced by CI (`.github/workflows/tests.yml`) and `test-via-pcsc/build_fido_tests.sh`. It is **not** committed to this repo (see `.gitignore`); CI checks it out into a sibling directory at runtime.

---

## Key Source Files

| File | Role |
|---|---|
| `src/device.c` | Main loop dispatch (`device_loop`), LED, touch, applet-session management |
| `src/apdu.c` | APDU parsing, chaining (`apdu_input`/`apdu_output`), shared I/O buffer |
| `src/key.c` | Key import/export, `ck_key_t` serialization, PIV/OpenPGP stream parsers |
| `src/pin.c` | PIN creation, verification, retry counter (backed by LittleFS) |
| `src/fs.c` | Thin LittleFS wrapper (`read_file`, `write_file`, `read_attr`, …) |
| `src/pke.c` | Platform key-engine buffer abstraction (hardware accelerator scratch space) |
| `interfaces/USB/class/ctaphid/ctaphid.c` | CTAPHID framing, channel management, `CTAPHID_Loop` |
| `interfaces/USB/class/ccid/ccid.c` | CCID T=1 framing, `CCID_Loop` |
| `interfaces/USB/device/usbd_desc.c` | USB descriptors (config, BOS, string) |

---

## Build System

CMake 3.16+, C11. The library target is `canokey-core`.

### Feature flags (CMake options / `-D`)

| Flag | Default | Effect |
|---|---|---|
| `ENABLE_NFC` | auto (from `HW_VARIANT`) | Compile NFC interface and NDEF applet |
| `ENABLE_APPLET_NDEF` | = `ENABLE_NFC` | Include NDEF applet |
| `ENABLE_IFACE_CTAPHID` | 1 | CTAPHID HID interface |
| `ENABLE_IFACE_CCID` | 1 | CCID interface |
| `ENABLE_IFACE_WEBUSB` | 1 | WebUSB vendor interface |
| `ENABLE_IFACE_KBDHID` | auto (`HAS_TOUCH`) | Keyboard HID interface |
| `ENABLE_PASS` | auto (`HAS_TOUCH`) | PASS/KBDHID OTP applet |
| `ENABLE_DEBUG_OUTPUT` | ON | `DBG_MSG`/`ERR_MSG` via `printf` |
| `ENABLE_BYPASS_USER_PRESENCE` | OFF | Skip all touch checks (testing only) |
| `ENABLE_TESTS` | OFF | Build CMocka unit tests + virt-card |
| `ENABLE_FUZZING` | OFF | Build honggfuzz harness |
| `VIRTCARD` | OFF | Build only the virtual-card targets |

### Running unit tests

```bash
mkdir build && cd build
cmake .. -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
ctest --output-on-failure
```

---

## Platform Porting Contract

A platform port **must** implement every symbol declared in `include/device.h`:

### Mandatory

```c
void     device_delay(int ms);
uint32_t device_get_tick(void);            // millisecond tick counter
int      device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking);
void     device_spinlock_unlock(volatile uint32_t *lock);
int      device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update);
void     led_on(void);
void     led_off(void);
void     device_set_timeout(void (*callback)(void), uint16_t timeout); // hardware timer with IRQ
```

### Mandatory for NFC (FM11NC SPI)

```c
void fm_csn_low(void);
void fm_csn_high(void);
void spi_transmit(const uint8_t *buf, uint8_t len);
void spi_receive(uint8_t *buf, uint8_t len);
```

### Mandatory for NFC (FM11NT I²C)

```c
void fm_csn_low(void); void fm_csn_high(void);
void i2c_start(void); void i2c_stop(void); void scl_delay(void);
fm_status_t i2c_read_ack(void); void i2c_send_ack(void); void i2c_send_nack(void);
fm_status_t i2c_write_byte(uint8_t data); uint8_t i2c_read_byte(void);
```

### Mandatory from `rand.h`

```c
uint32_t random32(void);
void     random_buffer(uint8_t *buf, size_t len);
```

Both are required: applet install paths (`ctap_install`, `piv_install`, virt-card fabrication) call `random_buffer` directly, not via `random32`.

### Platform hardware key engine (optional)

If the platform has hardware PKE registers, set `PLATFORM_HAS_PKE_BUFFER=1` and implement the functions declared in `include/pke.h`.  
Without it, `src/pke.c` provides a software fallback backed by a static RAM buffer.

### Main loop integration

```c
// Call in the main loop (every iteration):
device_loop();          // dispatches CCID_Loop / CTAPHID_Loop / WebUSB_Loop / KBDHID_Loop

// Call from a periodic interrupt (e.g. SysTick at 1 kHz):
device_update_led();

// Call when touch sensor fires:
set_touch_result(TOUCH_SHORT /* or TOUCH_LONG */);

// Call when NFC field appears/disappears:
set_nfc_state(1 /* or 0 */);
```

---

## Core Concepts

### APDU flow

```
Transport (CCID / CTAPHID / WebUSB / NFC)
  │  builds CAPDU, calls process_apdu()
  ▼
apdu.c: process_apdu() → dispatches to applet via applets.c
  ▼
Applet handler returns RAPDU (SW + data)
  ▼
Transport sends response
```

- `shared_io_buffer` is a single shared RAM region. Callers must call `acquire_apdu_buffer(owner)` / `release_apdu_buffer(owner)` around every transaction.
- APDU chaining (`CAPDU_CHAINING` / `RAPDU_CHAINING`) is handled transparently by `apdu_input` / `apdu_output`.

### Applet session

`device_applet_session_acquire(owner)` / `_release()` serialize multi-step cryptographic transactions (e.g. key generation) across loop iterations.  
Sessions expire after `APPLET_SESSION_TIMEOUT_MS` (2 s) of inactivity.

- Treat the applet session as the exclusivity boundary for large transient state. `CTAPHID`, CTAP over APDU (`CCID` / `WebUSB`), `OpenPGP`, and `PIV` are not required to make forward progress concurrently, so they should share one global session scratch area instead of reserving separate worst-case buffers per applet.
- Transport choice does not create a separate scratch domain: `CTAPHID`, `CCID`, and `WebUSB` all compete for the same session-level transient resources.
- The cross-applet exclusivity is enforced by `device_applet_session_acquire` in `src/device.c`. Per-applet helpers like `openpgp_crypto_acquire`, `openpgp_pke_acquire`, and `piv_pke_acquire` are bookkeeping flags inside the applet, **not** synchronization primitives — never call them as a substitute for an applet-session acquire.

### Touch / user-presence

`wait_for_user_presence(entry)` blocks inside the main loop, sending CTAPHID keep-alive frames, until a touch event is detected or a 30 s timeout fires.  
`BYPASS_USER_PRESENCE` (compile-time) and `testmode_emulate_user_presence()` (test-time) can skip this.

### File system

LittleFS is used for all persistent storage.  
`src/fs.c` wraps it with simple `read_file` / `write_file` / `read_attr` / `write_attr` helpers.  
The platform must supply an `lfs_config` struct and pass it to `fs_mount()` at boot.

### Key storage (`src/key.c`)

Keys are stored as `ck_key_t` blobs on LittleFS.  
`ck_key_t` contains `key_meta_t` (type, origin, usage, PIN/touch policy) plus a union of `rsa_key_t` / `ecc_key_t`.  
Import parsers consume both OpenPGP and PIV TLV wire formats incrementally via `ck_parse_openpgp_stream_*` / `ck_parse_piv_stream_*` so chained APDUs carrying RSA4096 templates do not need to be reassembled in RAM.

### Crypto

Crypto primitives live in the `canokey-crypto` submodule (`include/` exposed under `canokey-crypto/include/`).  
Platforms may override weak symbols to redirect to hardware accelerators (SE, PKE engine, etc.).

---

## Resource Constraints & Design Decisions

### ROM-saving rules

- In release builds, always set `ENABLE_DEBUG_OUTPUT=OFF` and add `-DLFS_NO_DEBUG -DLFS_NO_WARN -DLFS_NO_ERROR -DLFS_NO_ASSERT` to eliminate all LittleFS log strings.
- Do **not** add new unconditional `printf` / string-literal logging; use `DBG_MSG` / `ERR_MSG` only.
- Avoid duplicating large lookup tables or near-identical code paths for different key sizes; factor shared logic instead.

### RAM / stack

- There is no dynamic allocation (`malloc` is not used in firmware). Large temporaries must come from one of three places only: `shared_io_buffer`, one global applet-session scratch buffer, or the platform PKE register file.
- **Stack budget for any single call path: ≤ 5 KB total.** Crypto call paths are the primary consumers; see `canokey-ciu/AGENTS.md` for platform-specific spill rules.

### Streaming / scratch-space policy

- The current `applet_session_scratch_t` pattern must be treated as a single global scratch reservation, not as permission to grow per-applet dedicated buffers. Do not design new long-lived scratch members around applet ownership.
- `CTAPHID`, CTAP over `CCID` / `WebUSB`, `OpenPGP`, and `PIV` should share the same session scratch because only one of them is expected to own the applet session at a time.
- Size that global scratch for the largest **non-streamable** artifact only. The design target is an RSA-4096 result (`4096 / 8 = 512` bytes) plus small ASN.1 / TLV wrapper overhead, not an entire request or response payload.
- `applet_session_scratch_t` is a `union` of `ctap_ga` / `ctap_mldsa` / `buffer[APPLET_SHARED_BUFFER_LENGTH]`; the larger members alias the encoder buffer. Any field of `ctap_ga` that must survive an encoder write **must** sit past `APPLET_SHARED_BUFFER_LENGTH` bytes from the start of the union; static asserts in `include/applet-scratch.h` pin the current set. Re-arranging fields without checking this will silently let response generation corrupt parsed input.
- Everything else should be streamed: large APDU request bodies, large APDU responses, CTAP CBOR payloads, key-import TLVs, certificates, and public-key encodings should be parsed, encoded, and emitted incrementally whenever the protocol allows it.
- `shared_io_buffer` remains the short-APDU working buffer. Do not increase `APDU_BUFFER_SIZE` or add parallel heap-like buffers to avoid implementing streaming.
- PKE RAM may be used as **transient staging** for streaming input/output, but it is not stable storage. Any crypto operation, key-generation step, or helper that reuses the PKE engine may overwrite it.
- Therefore, any bytes or parser state that must survive across a crypto call, `device_loop()` iteration, keepalive, user-presence wait, or applet-session yield must not live only in PKE RAM. Move it into the global session scratch, `shared_io_buffer`, persistent storage, or recompute it.
- Before invoking crypto that may touch PKE, either fully consume the staged bytes already in PKE RAM or copy the surviving portion elsewhere first.
- When adding a new flow, document explicitly which parts are streamed, which exact bytes are forced to materialize, and why they cannot be streamed further.

### CTAP request lifetime

CTAP handlers must treat transport-backed request bytes as short-lived input, not as command state. A safe source-backed command lifecycle is:

1. Build a `ctap_req_src_t` from the transport source.
2. Parse every required request field from that source.
3. Copy only semantic fields into command state.
4. Clear the request source.
5. Continue with keepalive, user-presence waits, crypto, storage, and response generation.

`ctap_req_src_t` carries `read(ctx, offset, buf, len)` for pulling bytes plus an optional `cancelled(ctx)` callback, invoked on every read so cooperative cancellation (host-side CTAPHID CANCEL) terminates parsing immediately. Sources that cannot be cancelled may leave `cancelled` NULL.

If a command needs raw request bytes after parsing, handle the exact bytes before the first unsafe boundary:

- Materialize only the required range into stable RAM if it is bounded and non-streamable.
- Or consume the range immediately while the source is valid, such as hashing it or building a PIN/UV-token verification message.
- Or redesign the parser/handler contract so later phases never re-read transport storage.
- Do not use LittleFS as generic transport RX scratch just to cross an internal lifetime boundary. Flash writes are acceptable only when the CTAP protocol is writing persistent state, or for a narrowly documented protocol state machine with explicit size limit, trigger, erase point, and flash-wear rationale.

Unsafe boundaries include `KEEPALIVE()`, `WAIT()`, user-presence waits, `device_loop()`, applet-session yield/release, PIN/UV-token verification, credential key generation, assertion signing, ML-DSA streaming, and any helper that may call crypto or use PKE.

### PKE RAM usage contract

`pke_buffer_*()` is a staging API, not a persistence API:

- On platforms without hardware PKE buffer support, core provides a RAM fallback sized by `PKE_BUFFER_SIZE`.
- On CIU, the logical PKE buffer maps to the hardware PKE register file. The public capacity is still `pke_buffer_size()` / `PKE_BUFFER_SIZE`.
- `pke_buffer_acquire(owner)` only prevents intentional concurrent staging through the explicit API. It does not guarantee that bytes survive direct PKE-engine use.
- ECC, RSA, ML-DSA, PIN-token verification helpers, key generation, signature generation, keepalive side effects, file/key helpers, or response generation may indirectly clobber PKE RAM.

Allowed PKE staging uses:

- Stage a large input fragment while the next consumer immediately parses it through `ctap_req_src_t`.
- Stream bytes out of PKE only until the first operation that can touch crypto, send keepalive, call `WAIT()`, call `device_loop()`, or yield/release the applet session.
- Use PKE as a handoff buffer between transport framing and parser consumption, then clear the request source before later CTAP processing.

Forbidden PKE staging uses:

- Treat PKE as stable request storage after parser completion.
- Keep offsets into PKE for later verification, hashing, file writes, or response streaming.
- Read PKE-backed request bytes after keepalive, `WAIT()`, PIN/UV-token verification, credential key generation, assertion signing, ML-DSA streaming, or any operation that may call crypto.

### APDU transport: chaining, not extended length

**Rule: use ISO 7816-4 command/response chaining (`CAPDU_CHAINING` / `RAPDU_CHAINING`), not extended-length APDUs, for all multi-block data.**

- `APDU_BUFFER_SIZE` is 256 bytes (one short APDU payload). `APDU_COMMAND_BUFFER_SIZE = APDU_BUFFER_SIZE + 32 = 288 bytes`.
- `APDU_INCOMING_DATA_SIZE` is an alias for `APDU_COMMAND_BUFFER_SIZE` (288). Chained reassembly in `apdu_input` accumulates up to that limit, so applet bounds checks should compare against `APDU_INCOMING_DATA_SIZE`, not the raw 256-byte payload size.
- Extended-length APDUs (Lc/Le up to 65535) are **not supported** in the standard transport path.
- Large request data (e.g. RSA key import, FIDO2 CBOR) must be sent by the host as chained `CLA=0x10` commands; `apdu_input` reassembles them transparently.
- Large response data is returned via `GET RESPONSE` chaining; `apdu_output` handles segmentation transparently.
- Do **not** increase `APDU_BUFFER_SIZE` to work around a design that should use chaining.

### Streaming response sources

`apdu_response_source_set(total_len, sw, read, close, ctx)` registers a pull-based response stream with `apdu.c`:

- `read(ctx, offset, buf, len)` produces response bytes on demand; the framework calls it once per `GET RESPONSE` chunk.
- `close(ctx)` releases any backing resource (PKE buffer, shared scratch, file handle) when the stream finishes or is preempted.
- `apdu_response_source_clear()` is invoked automatically before the next non-`GET RESPONSE` command and on session expiry; applets may also call it directly to abort a stream.
- `apdu_response_source_active()` reports whether a stream is in flight (used by transports to decide between inline and chunked responses).

Use this helper for any response that does not fit `APDU_BUFFER_SIZE` instead of materializing the full payload into a buffer. PIV `7C` wrappers, OpenPGP large public-key encodings, FIDO2 large credential lists, and OpenPGP cert reads all go through this path.

### CTAP transport entrypoints

`CTAPHID_Execute_Cbor()` receives a full HID CBOR message:

- Requests up to `CTAPHID_INLINE_BUFSIZE` live in `channel.data`.
- Larger requests may live in PKE-backed RX staging.
- HID RX staging may back a `ctap_req_src_t` only while the command is still parsing bytes and before any operation that may reuse PKE.
- `authenticatorGetInfo` should emit from const segments. Large `makeCredential`, `getAssertion`, and credential-management responses may stream from prepared memory, files, or generated segments.

`CTAPHID_Execute_Msg()` wraps CTAP APDU over HID:

- The APDU header is small and can be copied to stack.
- The APDU data field may be source-backed.
- U2F APDUs are direct-memory users and require stable contiguous input.
- Do not point `CAPDU.data` at stack header storage for source-backed requests. Source-backed APDU paths must not dereference `DATA` for the payload except for deliberately materialized bytes.

CTAP over `CCID` / `WebUSB` / NFC APDU:

- Short request bodies live in `shared_io_buffer` only for the current APDU processing call. They are not long-lived across transport re-entry, `device_loop()`, session yield, or response streaming.
- CCID `XfrBlock`, WebUSB control requests, and NFC I-block aggregation are bounded by `APDU_COMMAND_BUFFER_SIZE`.
- FIDO APDU chaining is separate from transport frame aggregation. Once the FIDO APDU body spans multiple APDUs or exceeds the short incoming data limit, `fido_apdu_input()` stages the accumulated payload in PKE and dispatches through `ctap_process_pke_apdu_with_src()`.
- Chained FIDO APDU input in PKE follows the same lifetime rule as CTAPHID PKE-backed RX: it is valid only for immediate parser consumption.
- `process_apdu()` may clear the PKE-backed FIDO request after the first `apdu_output()` call. APDU response sources must never depend on request PKE.
- NFC pending storage must not become a general escape hatch for large request snapshots. Prefer parsed or bounded RAM pending state; treat whole-request file snapshots as implementation debt unless strictly justified.

### CTAP command lifecycle

| CTAP command | Request bytes after parse? | Boundary after parse? | Response streaming | Rule |
|---|---:|---:|---:|---|
| `makeCredential` | No, for normal fields | Yes | Yes | Parser copies semantic fields into `CTAP_make_credential`; P-9/P-10 sized HID requests should parse from source and stop using original bytes before keepalive, PIN verification, UP wait, or key generation. |
| `getAssertion` | No, for normal fields | Yes | Yes | Parser copies request fields into global assertion state; `getNextAssertion` reuses parsed state, not original CBOR. |
| `getNextAssertion` | No request body | No new parse | Yes | Uses stored assertion state and credential counter. |
| `getInfo` | No request body beyond command byte | No | Yes | Emit const/static response segments with small dynamic patches. |
| `clientPIN` | No | Crypto only | Usually no | Parser copies encrypted inputs, key agreement, permissions, RP hash, and auth parameters before crypto. |
| `credentialManagement` | Sometimes | Sometimes | Yes | `subCommandParams` may be needed for PIN-token verification; materialize exactly those bytes or compute/verify while the source is valid. Do not keep a PKE-backed reread source across keepalive or crypto. |
| `largeBlobs` | Yes for `set` | Yes | Limited | `set` bytes are needed for SHA-256/PIN-token verification and later `LB_FILE_TMP` writes. Do not pre-write unauthenticated `set` bytes to LittleFS and do not keep PKE offsets across verification unless every supported platform proves that path cannot clobber PKE. |
| `selection` | No request body beyond command byte | UP wait | No | Only performs user-presence wait. |
| `reset` | No request body beyond command byte | No | No | Time-gated reset only. |
| `config` | No | No | No | Currently unhandled. |

For `largeBlobs.set`, choose and document one command-specific contract before enabling source-backed PKE input: prove PIN-token verification cannot clobber PKE, materialize exactly the `set` fragment within the shared scratch budget, or redesign the handler so authorization happens before any second payload use.

### Endianness

- Always use `htobe32` / `be32toh` / `htole32` / `letoh32` / `htobe16` from `common.h` instead of system headers or manual shifts.
- `common.h` does not provide 16-bit little-endian helpers; either derive them via `LO()`/`HI()` or write the two bytes directly.
- USB wire data is little-endian; APDU/smartcard data is big-endian. Convert at the interface boundary.

---

## Coding Conventions

- C11, `-Wall`, Apache-2.0 license header on all new files.
- `DBG_MSG` / `ERR_MSG` macros for debug output; no bare `printf` in library code.
- `UNUSED(x)` macro to suppress unused-parameter warnings.
- `__packed` / `__weak` are defined in `common.h`; do not use raw GCC attributes directly.
- `htobe32` / `htole32` / `be32toh` are endianness helpers defined in `common.h`; do not use system headers that may be absent on bare-metal targets.
- `EXCEPT(sw_code)` macro sets `rapdu->sw` and returns from an applet handler early.
- Feature guards: always wrap interface-specific includes and calls in `#if ENABLE_IFACE_xxx`.
- Protocol-visible behavior changes must update the nearby public/developer documentation and include short comments for non-obvious security or interoperability constraints. For APDU extensions, document the command shape, authentication preconditions, persistent side effects, retry/range limits, and expected tests in the same change.

---

## Testing

| Suite | How to run |
|---|---|
| CMocka unit tests | `ctest` after building with `-DENABLE_TESTS=ON` |
| FIDO2 conformance | `virt-card/fido-hid-over-udp` + `fido2-tests/` |
| PC/SC integration | `u2f-virt-card` shared library + `test-via-pcsc/` |
| Real-hardware tests | `test-real/` (requires a physical device) |
| Fuzzing | `fuzzer/run-fuzzer.sh honggfuzz <id>` with `-DENABLE_FUZZING=ON` |

Test-mode extras (enabled by `TEST` define):
- `testmode_emulate_user_presence()` — auto-confirms touch
- `testmode_get_is_nfc_mode()` — reads NFC emulation config from file
- `testmode_inject_error()` — injects storage errors for fault testing
- `testmode_set_initial_ticks(uint32_t)` — pin the device tick counter to a known value (used by the virt-card and the MAGIC REBOOT path)
- `testmode_err_triggered(path, file_wr)` — query whether the most recent injected error fired for a given file/operation

---

## Common Pitfalls

- **Do not** call `CCID_Loop` / `CTAPHID_Loop` / etc. directly from interrupt context; they must run from the main loop thread only.
- **Do not** hold `shared_io_buffer` across a `device_loop()` call; another interface may attempt to acquire it.
- **Do not** assume PKE RAM survives a crypto operation. If data staged there is still needed after the next crypto step, copy it out first.
- **Do not** add separate worst-case scratch buffers for `CTAP`, `OpenPGP`, and `PIV`; if the data is not simultaneously live, it belongs in the shared session scratch.
- When adding a new applet, register it in `src/applets.c` and guard any new interface class source files in `CMakeLists.txt` with the appropriate `ENABLE_*` filter.
- `APDU_BUFFER_SIZE` (default 256) can be overridden by the platform via a compile-time define; ensure any new static buffers that alias `shared_io_buffer` respect `APDU_COMMAND_BUFFER_SIZE`, not the raw 256 value.
- LittleFS path strings are short (≤ 31 chars including the null terminator by default). Keep FS paths concise.
