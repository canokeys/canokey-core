#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the real USB control handler with mocked LL calls; no device needed."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="canokey-usb-test-") as directory:
    binary = str(Path(directory) / "test-usb")
    includes = ["include", "littlefs", "interfaces/USB/core/inc", "interfaces/USB/device"]
    command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
               "-ffunction-sections", "-fdata-sections", "-UNDEBUG", "-U__weak"]
    command += ["-I" + str(root / path) for path in includes]
    command += [str(root / "test/usb-endpoint/main.c"),
                str(root / "interfaces/USB/core/src/usbd_ctlreq.c"),
                "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections",
                "-o", binary]
    subprocess.run(command, check=True)
    subprocess.run([binary], check=True)
