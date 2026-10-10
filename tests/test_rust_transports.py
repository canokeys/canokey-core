#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute transport regressions in product and native platform compositions."""
import argparse
import itertools
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/transport-tests")
    args = parser.parse_args()
    profiles = [("ccid", ("usb-ccid",)), ("hid", ("usb-hid",)),
                ("nfc", ("nfc",)),
                ("device", ("device-runtime", "nfc", "storage", "usb-hid",
                            "usb-keyboard", "usb-webusb"))]
    for enabled in itertools.product((False, True), repeat=3):
        interfaces = tuple(feature for feature, on in zip(
            ("usb-hid", "usb-keyboard", "usb-webusb"), enabled) if on)
        profiles.append((f"usb/{enabled}", ("usb-device", *interfaces)))
    for native in (False, True):
        for name, features in profiles:
            features = ("static-backend", *features, *(("native-platform",) if native else ()))
            print(f"Testing {name}, native-platform={native}: {','.join(features)}", flush=True)
            subprocess.run(["cargo", "test", "-p", "canokey-rust-ffi",
                            "--no-default-features", "--features", ",".join(features),
                            "--target-dir", str(args.target_dir), "--lib"],
                           cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
