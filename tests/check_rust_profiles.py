#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile supported applet profiles and every USB interface combination."""
import itertools
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILES = {
    "none": (),
    "admin-pass": ("admin", "pass"),
    "oath": ("admin", "pass", "oath"),
    "openpgp": ("admin", "pass", "oath", "openpgp"),
    "piv": ("piv",),
    "ctap": ("admin", "ctap"),
    "full": ("admin", "pass", "oath", "openpgp", "piv", "ctap", "ndef"),
}


def check(name, features):
    print(f"Checking {name}: {','.join(features)}", flush=True)
    subprocess.run(
        ["cargo", "check", "-p", "canokey-rust-ffi", "--no-default-features",
         "--features", ",".join(features)], cwd=ROOT, check=True,
    )


def main():
    for name, applets in PROFILES.items():
        for backend in ("static-backend", "dynamic-backend"):
            check(f"{name}/{backend}", (backend, *applets))
    for applet in ("admin", "pass", "oath", "openpgp", "piv", "ctap", "ndef"):
        check(f"standalone/{applet}", ("static-backend", applet))
    for enabled in itertools.product((False, True), repeat=3):
        interfaces = tuple(feature for feature, on in zip(
            ("usb-webusb", "usb-hid", "usb-keyboard"), enabled) if on)
        check(f"usb/{enabled}", ("static-backend", "usb-device", *interfaces))
    check("nfcc", ("static-backend", "device-runtime", "nfc", "usb-webusb",
                   "usb-hid", "usb-keyboard", *PROFILES["full"]))
    check("restricted", ("static-backend", "ctap-restrict-algorithms"))


if __name__ == "__main__":
    main()
