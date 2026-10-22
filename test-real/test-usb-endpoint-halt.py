#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise CTAPHID IN endpoint halt requests on one connected CanoKey.

Requires PyUSB/libusb and python-fido2. Temporarily halts endpoint 0x82;
close applications using the key before running. No credentials are changed.
"""

import usb.core
import usb.util
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2


def main():
    devices = list(usb.core.find(find_all=True, idVendor=0x20A0, idProduct=0x42D4))
    if len(devices) != 1:
        raise RuntimeError("Connect exactly one CanoKey (20a0:42d4)")
    device = devices[0]
    endpoint = 0x82
    config = device.get_active_configuration()
    if not any(ep.bEndpointAddress == endpoint and (ep.bmAttributes & 3) == 3
               for interface in config for ep in interface):
        raise RuntimeError("CTAPHID interrupt IN endpoint 0x82 is not configured")

    def request(name, direction, request_id, length, expected):
        value = device.ctrl_transfer(direction, request_id, 0, endpoint, length, timeout=2000)
        result = value if isinstance(value, int) else bytes(value)
        if result != expected:
            raise AssertionError(f"{name}: got {result!r}, expected {expected!r}")
        print(f"PASS {name}", flush=True)

    try:
        request("initial status", 0x82, 0, 2, b"\x00\x00")
        request("clear an unhalted endpoint", 0x02, 1, None, 0)
        request("status after direct clear", 0x82, 0, 2, b"\x00\x00")
        request("set halt", 0x02, 3, None, 0)
        # Compare wire bytes: native uint16_t comparisons can hide endian bugs.
        request("halted status is little-endian", 0x82, 0, 2, b"\x01\x00")
        request("clear halt", 0x02, 1, None, 0)
        request("restored status", 0x82, 0, 2, b"\x00\x00")
    finally:
        try:
            device.ctrl_transfer(0x02, 1, 0, endpoint, None, timeout=2000)
        finally:
            usb.util.dispose_resources(device)

    for hid in CtapHidDevice.list_devices():
        if hid.descriptor.vid != 0x20A0 or hid.descriptor.pid != 0x42D4:
            hid.close()
            continue
        try:
            payload = b"CanoKey endpoint halt recovery"
            if hid.ping(payload) != payload:
                raise AssertionError("CTAPHID PING response mismatch")
            print("PASS CTAPHID PING after halt recovery")
            info = Ctap2(hid).get_info()
            print("PASS CTAP2 GetInfo:", info.versions)
        finally:
            hid.close()
        break
    else:
        raise RuntimeError("No CanoKey HID device after halt recovery")


if __name__ == "__main__":
    main()
