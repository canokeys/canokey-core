# Canokey Core

[![Tests](https://github.com/canokeys/canokey-core/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/canokeys/canokey-core/actions?query=branch%3Amaster)
[![Coverage](https://coveralls.io/repos/github/canokeys/canokey-core/badge.svg?branch=master)](https://coveralls.io/github/canokeys/canokey-core?branch=master)
[![Apache License 2.0](https://img.shields.io/badge/license-apache2.0-blue.svg)](https://github.com/canokeys/canokey-core/blob/master/LICENSE)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core?ref=badge_shield)

## Introduction

Core implementations of an open-source security key, supporting:

* U2F / FIDO2 with ed25519 and HMAC-secret
* OpenPGP Card V3.4, [Supported Algorithm List](https://docs.canokeys.org/userguide/openpgp/#supported-algorithm)
* PIV (NIST SP 800-73-4 plus CanoKey RSA, EC, Ed/X25519, SM2, and PQC
  algorithm extensions)
* HOTP / TOTP
* NDEF

The USB mode contains 3 different interfaces:

* Interface 0: U2F / FIDO2, which is an HID interface
* Interface 1: PIV/OpenPGP/OATH Card, which is a CCID interface
* Interface 2: WebUSB, which is not a standard interface
* Interface 3: Keyboard

The WebUSB interface is used to configure the key via a web-based interface.

## Protocol

Please refer to the [documentation](https://docs.canokeys.org/development/protocols/).

### PIN Retry Configuration Extensions

This core implements vendor APDUs for configuring PIV and OpenPGP retry limits. Retry counts must be in the range `1..15`; `15` is the maximum because failed-verification warnings are returned as `63Cx`.

The PIV management key in slot 9B uses AES-192 (`0x0A`) exclusively. Its factory value remains `010203040506070801020304050607080102030405060708`, matching YubiKey 5.7 and later.

- PIV: `00 FA <pinRetries> <pukRetries>` with no data. The command requires management-key authentication and PIN verification, resets PIN to `123456\xFF\xFF`, resets PUK to `12345678`, and installs the requested retry limits.
- OpenPGP: `00 F2 00 00 03 <pw1Retries> <resetCodeRetries> <pw3Retries>`. The command requires PW3 verification, resets PW1 to `123456`, resets PW3 to `12345678`, and updates the reset-code retry limit.

### OpenPGP Algorithms

OpenPGP supports RSA-2048/3072/4096, P-256/P-384/P-521, secp256k1,
Ed25519 (SIG/AUT), and X25519 (DEC). Algorithm information (`00 CA 00 FA`)
lists eight algorithms per slot; SM2 is no longer supported by this applet.
Setting SM2 algorithm attributes with `00 DA 00 C1/C2/C3`, after PW3
verification, returns `6A80` without changing the slot.

SM2 follows the OpenPGP algorithms in `key_type_t`, so OpenPGP excludes it
using the enumeration bound. This reorders persisted key type numbers:
reset OpenPGP and PIV storage when upgrading from the previous enum layout.
PIV and CTAP still support SM2. PIV reuses curve OIDs from the shared
attribute table to avoid duplicate ROM data.

Host OpenPGP tests cover the supported algorithm list.
PIV attestation tests verify the retained curve OIDs, including SM2.

### PIV Algorithm Extensions

The PIV applet supports RSA-2048, NIST P-256/P-384, and the following
algorithm-extension key types: RSA-3072, RSA-4096, P-521, secp256k1, SM2,
Ed25519, X25519, ML-DSA-65, and ML-KEM-768. Extension algorithm identifiers
are stored in a card configuration record and may be changed through the
authenticated algorithm-extension APDU (`00 EE`). Clients must read that
record rather than assuming the documented default bytes. ML-DSA signs and
ML-KEM decapsulates on card; ML-DSA verification and ML-KEM encapsulation are
host-side responsibilities. The PIV random command (`00 84`) is available on
firmware version 6.0 and newer.

### CTAP SM2 Configuration and Credential Enumeration

ADMIN SM2 configuration uses `00 11 00 00 08` to read and
`00 12 00 00 08 <curve_id> <algo_id>` to write. Both require ADMIN PIN
verification. The payload retains the packed pair of signed 32-bit integers
in device-native byte order (big-endian on CIU). A successful write persists
the configuration and updates the active identifiers. Wrong payload lengths
return `6700`; invalid identifiers return `6A80` without changing the configuration.

Curve ID 0 is reserved. IDs 1 through 8 and 256 through 259 identify other
curves in the IANA COSE registry (2026-09) and are rejected for SM2. Unassigned
IDs remain accepted for compatibility, including the default 9; values below
-65536 are reserved for private use by RFC 9053. Clients must agree on the
SM2 mapping and monitor future registry assignments for conflicts. Algorithm
IDs must not collide with ES256 (-7), EdDSA (-8), or ML-DSA-65 (-49). Both
identifiers support the full signed 32-bit encoding.

CTAP reset (including ADMIN CTAP reset) and reconstruction of incomplete
CTAP storage preserve valid SM2 configuration. Missing or invalid configuration
is replaced by the defaults `(curve_id=9, algo_id=-54)`. Attestation private-key
provisioning still initializes the defaults. Reset continues to erase credentials,
clear the PIN and rotate credential secrets; preserving SM2 identifiers does not
preserve credentials. Changing identifiers while credentials exist can invalidate
their algorithm mapping.

Credential-management enumeration returns SM2 as an EC2 COSE key with the
configured identifiers and both coordinates. ML-DSA-65 returns an AKP key
`{1: 7, 3: -49, -1: publicKey}` with a 1952-byte public key, generated from
the credential seed and streamed over HID or APDU `GET RESPONSE` chaining.
The vendor `subCommandParams[0x80]=true` option on EnumerateCredentialsBegin
omits public keys and returns `response[0x80]=algorithm`; this mode persists
through GetNext. Standard enumeration does not omit the public key.

Host APDU tests cover SM2 identifier validation, reset and storage recovery,
full-width COSE encoding, and mixed SM2/ES256/EdDSA/ML-DSA enumeration over
APDU and HID streams. ML-DSA public bytes are compared with seed-derived keys;
the metadata-only Begin/GetNext path is tested separately.

### CTAP SM2 Assertion Signatures

SM2 assertions follow GM/T 0003 rather than the FIDO ECDSA convention. The
authenticator computes `ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ xG ‖ yG ‖ xA ‖ yA)` on
card with the default user ID `1234567812345678` (GM/T 0009), then signs
`e = SM3(ZA ‖ authData ‖ clientDataHash)`. The signature is returned as the
raw 64-byte `r ‖ s` byte string (matching the FIDO MDS `sm2_sm3_raw` signature
encoding), not DER. Relying parties must verify with the same
`SM3(ZA ‖ M)` construction and the same default ID; a standard ECDSA/SHA-256
verifier cannot validate SM2 assertions. Attestation statements are unaffected:
they are always signed by the device attestation key with ES256 over
SHA-256, regardless of the credential algorithm.

## Porting

Use [Canokey-STM32](https://github.com/canokeys/canokey-stm32) as an example.

1. You need to implement these functions in `device.h`:

   * `void device_delay(int ms);`
   * `uint32_t device_get_tick(void);`
   * `int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking);`
   * `void device_spinlock_unlock(volatile uint32_t *lock);`
   * `int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update);`
   * `void led_on(void);`
   * `void led_off(void);`
   * `void device_set_timeout(void (*callback)(void), uint16_t timeout);`
      * A hardware timer with IRQ is required

  If you need NFC, you also need to implement the following functions for FM11NT08:

  * `void fm_csn_low(void);`
  * `void fm_csn_high(void);`
  * `void i2c_start(void);`
  * `void i2c_stop(void);`
  * `void i2c_bus_recover(void);`
  * `void scl_delay(void);`
  * `fm_status_t i2c_read_ack(void);`
  * `void i2c_send_ack(void);`
  * `void i2c_send_nack(void);`
  * `fm_status_t i2c_write_byte(uint8_t data);`
  * `uint8_t i2c_read_byte(void);`

2. You must provide both `random32` and `random_buffer` in `rand.h`.

3. You need to configure the littlefs properly.

4. You need to configure the mbed-tls according to its documentation or provide the algorithms on your own by overwriting the weak symbols.

   Or instead, you may implement the cryptography algorithms by yourself.

5. You should call the `device_loop` or `nfc_loop` in the main loop, and the `device_update_led` in a periodic interrupt. 

6. You should call the `set_touch_result` to report touch sensing result, and `set_nfc_state` to report NFC state.

## Fuzz testing

Fuzzing uses AFL++ with ASan/UBSan. Instrumented builds require GNU GCC,
normally through `afl-gcc-fast`:

```bash
cmake -S . -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=afl-gcc-fast -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target afl-fuzzer --parallel
```

Then, run fuzzing tests (`${id}`: empty = CCID transport, 0..5 = PIV, CTAP,
OATH, Admin, OpenPGP, NDEF):

```bash
CANOKEY_FUZZ_APPLET=${id} afl-fuzz -i fuzzing/applet${id}/data -o fuzzing/applet${id}/findings -- ./build/afl-fuzzer
```

Crash artifacts are replayed directly with the same binary:
`CANOKEY_FUZZ_APPLET=${id} ./build/afl-fuzzer < crash-file`.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core?ref=badge_large)
