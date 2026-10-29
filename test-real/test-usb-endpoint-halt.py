#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise CTAPHID IN endpoint halt requests on one connected CanoKey.

Requires PyUSB/libusb and python-fido2. Temporarily halts endpoint 0x82;
close applications using the key before running. No credentials are changed.
"""

import argparse
import errno
import sys
import usb.core
import usb.util
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-absent-endpoint", action="store_true",
                        help="fail unless an in-range non-control endpoint is absent")
    args = parser.parse_args()
    devices = list(usb.core.find(find_all=True, idVendor=0x20A0, idProduct=0x42D4))
    if len(devices) != 1:
        raise RuntimeError("Connect exactly one CanoKey (20a0:42d4)")
    device = devices[0]
    endpoint = 0x82
    config = device.get_active_configuration()
    present = {ep.bEndpointAddress for interface in config for ep in interface}
    absent = [addr for number in range(1, 4) for addr in (number, number | 0x80)
              if addr not in present]
    if args.require_absent_endpoint and not absent:
        raise RuntimeError("Use firmware with an interface disabled for absent-endpoint coverage")
    if not any(ep.bEndpointAddress == endpoint and (ep.bmAttributes & 3) == 3
               for interface in config for ep in interface):
        raise RuntimeError("CTAPHID interrupt IN endpoint 0x82 is not configured")

    def request(name, direction, request_id, length, expected):
        value = device.ctrl_transfer(direction, request_id, 0, endpoint, length, timeout=2000)
        result = value if isinstance(value, int) else bytes(value)
        if result != expected:
            raise AssertionError(f"{name}: got {result!r}, expected {expected!r}")
        print(f"PASS {name}", flush=True)

    def reject(name, request_id, index, expected_status, direction=0x02, feature=0, length=None):
        try:
            device.ctrl_transfer(direction, request_id, feature, index, length, timeout=2000)
        except usb.core.USBError as error:
            if error.errno != errno.EPIPE:
                raise  # A timeout/disconnect is not an expected protocol STALL.
        else:
            raise AssertionError(f"{name}: invalid request succeeded")
        request(f"{name}: rejected; EP82 unchanged", 0x82, 0, 2, expected_status)

    def invalid_requests(expected_status):
        for request_id in (1, 3):
            if sys.platform == "darwin" and request_id == 1:
                print("SKIP malformed CLEAR on macOS: host result is not a reliable wire rejection check")
                continue
            for high_byte in (1, 0xFF):
                reject(f"request {request_id} reserved index {high_byte:02x}", request_id,
                       (high_byte << 8) | endpoint, expected_status)
            for addr in absent + [0, 0x80, 0x84, 0x92]:
                reject(f"request {request_id} invalid endpoint {addr:02x}", request_id,
                       addr, expected_status)
            reject(f"request {request_id} invalid feature", request_id, endpoint,
                   expected_status, feature=1)
            reject(f"request {request_id} invalid direction", request_id, endpoint,
                   expected_status, direction=0x82, length=0)
            reject(f"request {request_id} invalid length", request_id, endpoint,
                   expected_status, length=b"\x00")

    try:
        request("initial status", 0x82, 0, 2, b"\x00\x00")
        request("clear an unhalted endpoint", 0x02, 1, None, 0)
        request("status after direct clear", 0x82, 0, 2, b"\x00\x00")
        invalid_requests(b"\x00\x00")
        request("set halt", 0x02, 3, None, 0)
        # Compare wire bytes: native uint16_t comparisons can hide endian bugs.
        request("halted status is little-endian", 0x82, 0, 2, b"\x01\x00")
        invalid_requests(b"\x01\x00")
        request("clear halt", 0x02, 1, None, 0)
        request("restored status", 0x82, 0, 2, b"\x00\x00")
        if not absent:
            print("SKIP absent in-range endpoint: all endpoints are configured")
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
