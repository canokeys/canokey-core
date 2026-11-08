#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate literal largeBlobs vectors from independent CBOR/SHA-256 values.

Upload through real CTAP commands, then read file-backed responses through
CCID, WebUSB, native HID CBOR/MSG and NFC. No storage injection, product parser
or recorded implementation response is used to construct expected bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path

from fido2 import cbor

ROOT = Path(__file__).resolve().parents[2]
USB_AID = bytes.fromhex("f043414e4f464944")
NFC_AID = bytes.fromhex("a0000006472f0001")
SUCCESS = bytes.fromhex("9000")
VERSION = b"U2F_V2" + SUCCESS


def sw(remaining):
    return bytes([0x61, min(remaining, 255)]) if remaining else SUCCESS


def hid_reports(command, body):
    cid = bytes.fromhex("12345678")
    reports = [cid + bytes([command]) + len(body).to_bytes(2, "big") + body[:57].ljust(57, b"\0")]
    for sequence, offset in enumerate(range(57, len(body), 59)):
        reports.append(cid + bytes([sequence]) + body[offset:offset + 59].ljust(59, b"\0"))
    return reports


class Transport:
    def __init__(self, kind):
        self.kind = kind
        self.steps = []
        self.number = 0
        self.sequence = 0
        if kind == "ccid":
            self.ccid(0x62, b"", bytes.fromhex("3bf71100008131fe6543616e6f6b657999"))
        if kind not in ("cbor", "msg"):
            aid = NFC_AID if kind == "nfc" else USB_AID
            self.apdu(b"\x00\xa4\x04\x00\x08" + aid + b"\x00", VERSION)

    def ccid(self, command, body, response):
        self.sequence += 1
        header = bytes([command]) + len(body).to_bytes(4, "little") + bytes([0, self.sequence, 0, 0, 0])
        raw = header + body
        reply = b"\x80" + len(response).to_bytes(4, "little") + bytes([0, self.sequence, 0, 0x81, 0]) + response
        for offset in range(0, len(raw), 64):
            self.steps.append(dict(packet=raw[offset:offset + 64].hex(),
                                   expected=reply.hex() if offset + 64 >= len(raw) else ""))

    def web(self, body, response):
        def setup(kind, request, length):
            return bytes([kind, request, 0, 0, 1, 0]) + length.to_bytes(2, "little")
        self.steps.append(dict(setup=setup(0x41, 0, len(body)).hex(), expected=""))
        self.steps.extend(dict(out=body[i:i + 16].hex(), expected="") for i in range(0, len(body), 16))
        self.steps.append(dict(in_=True, expected=""))
        self.steps.append(dict(setup=setup(0xc1, 1, len(response)).hex(), expected=response[:16].hex()))
        self.steps.extend(dict(in_=True, expected=response[i:i + 16].hex()) for i in range(16, len(response), 16))
        self.steps.extend([dict(in_=True, expected=""), dict(out="", expected="")])

    def hid(self, command, body, response, processing=False):
        frames = hid_reports(command, body)
        self.steps.extend(dict(hid=frame.hex(), expected="") for frame in frames)
        reports = (hid_reports(0xbb, b"\x01") if processing else []) + hid_reports(command, response)
        self.steps[-1]["expected_hid"] = b"".join(reports).hex()

    def nfc(self, body, response, aggregate=False, retransmit=False):
        # Internal source-backed APDU chunks are250 bytes. Extended FIDO hides their status
        # words, but retains the internal chunk boundaries in RF framing.
        segments = [response]
        if aggregate:
            segments = [response[i:i + 250] for i in range(0, len(response) - 2, 250)]
            # Status bytes belong to the final engine chunk.
            segments[-1] = segments[-1][:len(response) - 2 - 250 * (len(segments) - 1)] + response[-2:]
        outgoing = []
        for index, segment in enumerate(segments):
            for offset in range(0, len(segment), 29):
                more = offset + 29 < len(segment) or index + 1 < len(segments)
                outgoing.append((more, segment[offset:offset + 29]))
        chunks = [body[i:i + 29] for i in range(0, len(body), 29)]
        for index, chunk in enumerate(chunks):
            more = index + 1 < len(chunks)
            pcb = self.number | (0x12 if more else 0x02)
            if more:
                expected = bytes([0xa2 | self.number])
            else:
                chained, data = outgoing.pop(0)
                expected = bytes([self.number | (0x12 if chained else 0x02)]) + data
            self.steps.append(dict(packet=(bytes([pcb]) + chunk + b"\0\0").hex(), expected=expected.hex()))
            if more:
                self.number ^= 1
        if retransmit:
            self.steps.append(dict(packet=(bytes([0xb2 | self.number]) + b"\0\0").hex(), expected=expected.hex()))
        for chained, data in outgoing:
            self.number ^= 1
            request = bytes([0xa2 | self.number]) + b"\0\0"
            response = bytes([self.number | (0x12 if chained else 0x02)]) + data
            self.steps.append(dict(packet=request.hex(), expected=response.hex()))
        self.number ^= 1

    def apdu(self, body, response, **kwargs):
        processing = kwargs.pop("processing", False)
        if self.kind == "ccid":
            self.ccid(0x6f, body, response)
        elif self.kind == "webusb":
            self.web(body, response)
        elif self.kind == "msg":
            self.hid(0x83, body, response, processing)
        else:
            self.nfc(body, response, **kwargs)

    def request(self, body, response, limit=256, extended=False, drain=True, retransmit=False):
        if self.kind == "cbor":
            self.hid(0x90, body, response, processing=response[0] == 0)
            return
        native = self.kind == "msg"
        header = bytes.fromhex("80100000")
        if native or extended:
            raw = header + b"\0" + len(body).to_bytes(2, "big") + body + (limit % 65536).to_bytes(2, "big")
        else:
            parts = [body[i:i + 255] for i in range(0, len(body), 255)]
            for part in parts[:-1]:
                self.apdu(bytes.fromhex("90100000") + bytes([len(part)]) + part, SUCCESS)
            raw = header + bytes([len(parts[-1])]) + parts[-1] + bytes([limit % 256])
        capacity = limit if (extended or native and len(response) <= limit) else min(limit, 250)
        n = min(capacity, len(response))
        self.apdu(raw, response[:n] + sw(len(response) - n),
                  aggregate=extended and n > 250, retransmit=retransmit, processing=response[0] == 0)
        if drain:
            self.remaining(response, n, native)

    def remaining(self, response, offset, native):
        while offset < len(response):
            n = min(256 if native and len(response) - offset <= 256 else 250, len(response) - offset)
            raw = bytes.fromhex("00c000000000000100" if native else "00c0000000")
            self.apdu(raw, response[offset:offset + n] + sw(len(response) - offset - n))
            offset += n

    def get(self, blob, count, offset=0, **kwargs):
        result = b"\x03" if count > 1232 else b"\x02" if offset > len(blob) else b"\0" + cbor.encode({1: blob[offset:offset + count]})
        self.request(b"\x0c" + cbor.encode({1: count, 3: offset}), result, **kwargs)

    def upload(self, blob):
        for offset in range(0, len(blob), 1232):
            params = {2: blob[offset:offset + 1232], 3: offset}
            if offset == 0:
                params[4] = len(blob)
            self.request(b"\x0c" + cbor.encode(params), b"\0", extended=self.kind == "nfc")

    def case(self, name):
        for step in self.steps:
            if "in_" in step:
                step["in"] = step.pop("in_")
        return dict(id=f"{self.kind}-{name}", transport="usb" if self.kind in ("cbor", "msg") else self.kind,
                    oracle_rows=["C3", "E56"],
                    preconditions="Fresh throwaway storage, no PIN, alwaysUv false. Blob is uploaded through CTAP SET with SHA256 checksum; no file injection. Configured USB or activated NFC; HID IN drains per event. NFC CRC is chip-validated; no physical timing or storage faults modeled.",
                    steps=self.steps)


def generate():
    data = cbor.encode([bytes((73 * i + 19) % 256 for i in range(4076))])
    blob = data + hashlib.sha256(data).digest()[:16]
    assert len(blob) == 4096
    empty = b"\x80" + hashlib.sha256(b"\x80").digest()[:16]
    usb, nfc = [], []
    for kind in ["ccid", "webusb", "cbor", "msg", "nfc"]:
        output = nfc if kind == "nfc" else usb
        t = Transport(kind)
        for count, offset in [(1232, 0), (0, 0), (1, 17), (1, 18), (1233, 0)]:
            t.get(empty, count, offset)
        output.append(t.case("empty-boundaries"))
        t = Transport(kind)
        t.upload(blob)
        for offset in [0, 1232, 2464, 3696, 4096, 4097]:
            t.get(blob, 1232, offset)
        t.get(blob, 1233)
        output.append(t.case("4096-upload-clipped-reads"))
        if kind != "cbor":
            t = Transport(kind)
            t.upload(blob)
            for limit in [1, 2, 3, 4, 5, 249, 250, 251, 255, 256]:
                t.get(blob, 1232, limit=limit, retransmit=kind == "nfc")
            output.append(t.case("prefix-and-file-splits"))
    t = Transport("msg")
    t.upload(blob)
    for limit in [700, 1236, 1237, 65536]:
        t.get(blob, 1232, limit=limit)
    usb.append(t.case("partial-window-versus-complete-native-source"))
    for limit in [1, 250, 251, 255, 256, 257, 1237, 65536]:
        t = Transport("nfc")
        t.upload(blob)
        t.get(blob, 1232, limit=limit, extended=True, retransmit=True)
        nfc.append(t.case(f"extended-Le{limit}"))
    return usb, nfc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=ROOT / "tests/fixtures")
    args = parser.parse_args()
    for suffix, cases in zip(["usb", "nfc"], generate()):
        directory = args.output_root / f"c312-large-blob-{suffix}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "vectors.json").write_text(json.dumps(dict(schema=1,
            scope="CTAP largeBlobs segmented output using wire-provisioned deterministic4096-byte data. Exact bytes on actual pinned C and Rust transports; no storage fault, physical USB/RF/WTX or CIU resource acceptance.",
            cases=cases), indent=2) + "\n")
        print(suffix, len(cases), "cases", sum(len(c["steps"]) for c in cases), "events")


if __name__ == "__main__":
    main()
