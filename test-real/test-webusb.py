#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise CanoKey WebUSB descriptors and APDU transport on real hardware."""

import argparse
import time

import usb.core
import usb.util


WEBUSB_REQUEST = 0x01
WEBUSB_GET_URL = 0x02
MS_OS_20_REQUEST = 0x02
MS_OS_20_GET_DESCRIPTOR_SET = 0x07

WEBUSB_REQ_CMD = 0x00
WEBUSB_REQ_RESP = 0x01
WEBUSB_REQ_STAT = 0x02

VENDOR_IN_DEVICE = 0xC0
VENDOR_OUT_INTERFACE = 0x41
VENDOR_IN_INTERFACE = 0xC1


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vid", type=lambda value: int(value, 0), default=0x20A0)
    parser.add_argument("--pid", type=lambda value: int(value, 0), default=0x42D4)
    parser.add_argument("--interface", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=3.0)
    return parser.parse_args()


def webusb_apdu(device, interface, apdu, timeout):
    transferred = device.ctrl_transfer(
        VENDOR_OUT_INTERFACE,
        WEBUSB_REQ_CMD,
        0,
        interface,
        apdu,
        timeout=int(timeout * 1000),
    )
    if transferred != len(apdu):
        raise AssertionError(f"short WebUSB command transfer: {transferred}/{len(apdu)}")

    deadline = time.monotonic() + timeout
    while True:
        state = int(
            device.ctrl_transfer(
                VENDOR_IN_INTERFACE,
                WEBUSB_REQ_STAT,
                0,
                interface,
                1,
                timeout=int(timeout * 1000),
            )[0]
        )
        if state == 0:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(f"WebUSB response timed out in state {state}")
        time.sleep(0.01)

    return bytes(
        device.ctrl_transfer(
            VENDOR_IN_INTERFACE,
            WEBUSB_REQ_RESP,
            0,
            interface,
            4096,
            timeout=int(timeout * 1000),
        )
    )


def main():
    args = parse_args()
    device = usb.core.find(idVendor=args.vid, idProduct=args.pid)
    if device is None:
        raise SystemExit(f"CanoKey {args.vid:04x}:{args.pid:04x} not found")

    config = device.get_active_configuration()
    interface = config[(args.interface, 0)]
    if (
        interface.bInterfaceClass,
        interface.bInterfaceSubClass,
        interface.bInterfaceProtocol,
    ) != (0xFF, 0xFF, 0xFF):
        raise AssertionError(f"interface {args.interface} is not WebUSB")

    url_desc = bytes(
        device.ctrl_transfer(
            VENDOR_IN_DEVICE,
            WEBUSB_REQUEST,
            1,
            WEBUSB_GET_URL,
            255,
            timeout=int(args.timeout * 1000),
        )
    )
    if len(url_desc) < 4 or url_desc[1:3] != b"\x03\x01":
        raise AssertionError(f"invalid WebUSB URL descriptor: {url_desc.hex()}")
    landing_url = "https://" + url_desc[3:].decode("utf-8")

    ms_os_desc = bytes(
        device.ctrl_transfer(
            VENDOR_IN_DEVICE,
            MS_OS_20_REQUEST,
            0,
            MS_OS_20_GET_DESCRIPTOR_SET,
            0xB2,
            timeout=int(args.timeout * 1000),
        )
    )
    if len(ms_os_desc) != 0xB2 or ms_os_desc[:4] != b"\x0A\x00\x00\x00":
        raise AssertionError(f"invalid Microsoft OS 2.0 descriptor ({len(ms_os_desc)} bytes)")

    usb.util.claim_interface(device, args.interface)
    try:
        select = webusb_apdu(
            device, args.interface, bytes.fromhex("00A4040005F000000000"), args.timeout
        )
        version = webusb_apdu(
            device, args.interface, bytes.fromhex("0031000000"), args.timeout
        )
    finally:
        usb.util.release_interface(device, args.interface)

    if select != b"\x90\x00" or version[-2:] != b"\x90\x00":
        raise AssertionError(
            f"unexpected APDU status: select={select.hex()}, version={version.hex()}"
        )

    print(f"WebUSB interface: {args.interface}")
    print(f"Landing page: {landing_url}")
    print(f"Microsoft OS 2.0 descriptor: {len(ms_os_desc)} bytes")
    print(f"Firmware: {version[:-2].decode('ascii')}")


if __name__ == "__main__":
    main()
