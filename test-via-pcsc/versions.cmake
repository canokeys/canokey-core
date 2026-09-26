# SPDX-License-Identifier: Apache-2.0
# Host integration-test platform, not a product release configuration.
set(CANOKEY_FIDO_FIRMWARE_VERSION 0)
set(CANOKEY_CTAPHID_DEVICE_VERSION "0.0.0")
set(CANOKEY_USB_BCD_DEVICE 0x0000)
# External clients use these fields for protocol/capability selection. Preserve
# the compatibility versions used before platform-supplied release fields:
# piv-go treats a PIV major version below 5 as a legacy YubiKey, selects its
# unsupported OTP applet for serial reads, and skips modern PIV feature tests.
set(CANOKEY_PIV_VERSION "6.0.0")
set(CANOKEY_OATH_VERSION "6.0.0")
