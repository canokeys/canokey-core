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
├── fido2-tests/        # FIDO2 conformance test helpers
├── fuzzer/             # honggfuzz fuzzing harness
└── scripts/            # Code-generation scripts (gen_ctap_get_info.py)
```

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
// optional: void random_buffer(uint8_t *buf, size_t len);
```

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
Import parsers exist for both OpenPGP (`ck_parse_openpgp*`) and PIV (`ck_parse_piv*`) TLV wire formats, with streaming variants for large RSA keys.

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

- `shared_io_buffer` is the **only** large heap-like buffer. There is no dynamic allocation (`malloc` is not used in firmware). All large temporaries must either reuse `shared_io_buffer` (with proper acquire/release) or use the platform PKE register file.
- **Stack budget for any single call path: ≤ 5 KB total.** Crypto call paths are the primary consumers; see `canokey-ciu/AGENTS.md` for platform-specific spill rules.

### APDU transport: chaining, not extended length

**Rule: use ISO 7816-4 command/response chaining (`CAPDU_CHAINING` / `RAPDU_CHAINING`), not extended-length APDUs, for all multi-block data.**

- `APDU_BUFFER_SIZE` is 256 bytes (one short APDU payload). `APDU_COMMAND_BUFFER_SIZE = APDU_BUFFER_SIZE + 32 = 288 bytes`.
- Extended-length APDUs (Lc/Le up to 65535) are **not supported** in the standard transport path.
- Large request data (e.g. RSA key import, FIDO2 CBOR) must be sent by the host as chained `CLA=0x10` commands; `apdu_input` reassembles them transparently.
- Large response data is returned via `GET RESPONSE` chaining; `apdu_output` handles segmentation transparently.
- Do **not** increase `APDU_BUFFER_SIZE` to work around a design that should use chaining.

### Endianness

- Always use `htobe32` / `be32toh` / `htole32` / `letoh32` from `common.h` instead of system headers or manual shifts.
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

---

## Common Pitfalls

- **Do not** call `CCID_Loop` / `CTAPHID_Loop` / etc. directly from interrupt context; they must run from the main loop thread only.
- **Do not** hold `shared_io_buffer` across a `device_loop()` call; another interface may attempt to acquire it.
- When adding a new applet, register it in `src/applets.c` and guard any new interface class source files in `CMakeLists.txt` with the appropriate `ENABLE_*` filter.
- `APDU_BUFFER_SIZE` (default 256) can be overridden by the platform via a compile-time define; ensure any new static buffers that alias `shared_io_buffer` respect `APDU_COMMAND_BUFFER_SIZE`, not the raw 256 value.
- LittleFS path strings are short (≤ 31 chars including the null terminator by default). Keep FS paths concise.
