# Canokey Core

[![Build Status](https://travis-ci.com/canopo/canokey-core.svg?branch=master)](https://travis-ci.com/canopo/canokey-core)
[![Coverage Status](https://coveralls.io/repos/github/canopo/canokey-core/badge.svg?branch=master)](https://coveralls.io/github/canopo/canokey-core?branch=master)

## Introduction

Core implementations of an open-source secure key, with supports of:

* U2F / FIDO2
* OpenPGP Card V3.4 with ECDSA support
* PIV (NIST SP 800-73-4)
* TOTP

The USB mode contains 4 different interfaces:

* Interface 0: U2F / FIDO2, which is an HID interface
* Interface 1: OpenPGP Card, which is a CCID interface
* Interface 2: PIV and OATH, which is also a CCID interface
* Interface 3: WebUSB, which is not a standard interface

Although OpenPGP Card uses the CCID interface, we make it a unique one because the `gpg-agent` opens the card using the `exlusive` mode.
The WebUSB interface is used to configure the key via a web-based interface.

## Protocol

For interface 0-2, please refer to the corresponding standard.

For interface 3, you may use APDUs to use OpenPGP Card / PIV / OATH / Admin applets. The PIV applet in interface 3 only supports extended APDU mode.

### The protocol of admin applet

* AID: F0 00 00 00 00
* Instructions:
  * 20 Verify PIN
  * 21 Change PIN
  * 01 Write FIDO private key
  * 02 Write FIDO cert
  * 03 Reset OpenPGP applet
  * 04 Reset PIV applet
  * 05 Reset OATH applet
  * 30 Write SN

#### Verify PIN

The default PIN is "123456" (in string) or "31 32 33 34 35 36" (in hex). You need to verify your PIN before you do anything else. The verification is the same as the OpenPGP applet. Here is the example:

`00 20 00 00 06 31 32 33 34 35 36`

`9000`

The maximum length of the PIN is 64 bytes and the minimum length is 6 bytes.

#### Change PIN

After a successful verification, you can use this command to change your PIN DIRECTLY:

`00 21 00 00 08 31 31 31 31 31 31 31 31`

`9000`

Your PIN will be set to "11111111".

NOTE THAT THERE IS NO WAY TO RESET THE PIN OF THIS ADMIN APPLET.

#### Write FIDO private key

This is a EcDSA secp256r1 private key (32 bytes), and will be used in both U2F and FIDO2 to sign the registration data. Use a short APDU to set it:

`00 01 00 00 20 01 02 03 04 05 06 07 08 09 ..`

`9000`

Once you write a new private key, your old 2FA credentials will be INVALID.

#### Write FIDO certificate

This is a X.509 der certificate corresponding to your private key. Use a EXTENDED APDU to set it:

`00 02 00 00 00 LL LL DD DD ..`, LLLL is the length of the cert.

`9000`

#### Reset applets

Executing these commands will reset the corresponding applets.

#### Write SN

The SN can be only set ONCE. Due to the limitation of OpenPGP card spec, the serial number is 4-byte long.

`00 30 00 00 04 DE AD BE AF`
`9000`

## Porting

Use [Canokey-STM32](https://github.com/canopo/canokey-stm32) as an example.

1. You need to implement these functions in `device.h`:

* `void device_delay(int ms);`
* `uint32_t device_get_tick(void);`
* `void device_start_blinking(uint8_t sec);`
* `void device_stop_blinking(void);`
* `uint8_t is_nfc(void);`

2. You should also provide a `random32` and a optional `random_buffer` function in `rand.h`.

3. You need to configure the mbed-tls according to its documentation or provide the algorithms on your own by overwriting the weak symbols.

4. You should call the `device_loop` in the main loop, and call the `CCID_TimeExtensionLoop` every 150ms **IN A TIMER**.
