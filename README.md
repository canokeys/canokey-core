# Canokey Core

[![Tests](https://github.com/canokeys/canokey-core/workflows/tests/badge.svg?branch=master)](https://github.com/canokeys/canokey-core/actions?query=branch%3Amaster)
[![Coverage](https://coveralls.io/repos/github/canokeys/canokey-core/badge.svg?branch=master)](https://coveralls.io/github/canokeys/canokey-core?branch=master)
[![Apache License 2.0](https://img.shields.io/badge/license-apache2.0-blue.svg)](https://github.com/canokeys/canokey-core/blob/master/LICENSE)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core?ref=badge_shield)

## Introduction

Core implementations of an open-source secure key, with supports of:

* U2F / FIDO2 with ed25519 and HMAC-secret
* OpenPGP Card V3.4, [Supported Algorithm List](https://docs.canokeys.org/userguide/openpgp/#supported-algorithm)
* PIV (NIST SP 800-73-4)
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

  If you need NFC, you also need to implement the following functions:
  
  * `void fm_nss_low(void);`
  * `void fm_nss_high(void);`
  * `void fm_transmit(uint8_t *buf, uint8_t len);`
  * `void fm_receive(uint8_t *buf, uint8_t len);`

2. You should also provide a `random32` and a optional `random_buffer` function in `rand.h`.

3. You need to configure the littlefs properly.

4. You need to configure the mbed-tls according to its documentation or provide the algorithms on your own by overwriting the weak symbols.

   Or instead, you may implement the cryptography algorithms by yourself.

5. You should call the `device_loop` or `nfc_loop` in the main loop, and the `device_update_led` in a periodic interrupt. 

6. You should call the `set_touch_result` to report touch sensing result, and `set_nfc_state` to report NFC state.

## Virt Card (USB/IP)

For developing and user playing, a virtual canokey is implemented based on USB/IP.

Use the following commands to compile and you would find a `canokey-usbip` there.
```
cd build
cmake .. -DUSBIP=ON
```

Usage:
```
canokey-usbip [canokey-file [port [touch]]]
```

- `canokey-file`: the file system of the virtual canokey, default value: `/tmp/canokey-file`
- `port`: the port where usbip server listens on, default value 3240. Currently only localhost is supported. 
- `touch`: if presents, you could use `Ctrl-C` to issue an touch. Otherwise touch is ignored by the firmware.

## Fuzz testing

Install honggfuzz from source first, then enable fuzz tests:

```bash
cd build
cmake .. -DENABLE_FUZZING=ON -DENABLE_TESTS=ON -DCMAKE_C_COMPILER=hfuzz-clang -DCMAKE_BUILD_TYPE=Debug
```

Then, run fuzzing tests:

```bash
./fuzzer/run-fuzzer.sh honggfuzz ${id}
```


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcanokeys%2Fcanokey-core?ref=badge_large)
