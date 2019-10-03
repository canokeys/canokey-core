# Canokey Core

[![Build Status](https://travis-ci.org/canopo/canokey-core.svg?branch=master)](https://travis-ci.org/canopo/canokey-core)
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

