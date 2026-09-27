# SPDX-License-Identifier: Apache-2.0
"""Shared host transport, APDU client and TLV helpers."""

import subprocess
import time
from contextlib import contextmanager


class Host:
    def __init__(self, path):
        self.process = subprocess.Popen(
            [path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def command(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"host card exited: {self.process.poll()}"
        return bytes.fromhex(line.strip())

    def transmit(self, data):
        response = self.command(data.hex())
        return response[:-2], response[-2], response[-1]

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=5) == 0


@contextmanager
def connection(path):
    if path:
        card = Host(path)
        try:
            yield card
        finally:
            card.close()
    else:
        from devkit_ctl import CCIDConnection

        with CCIDConnection.open(mode="normal") as card:
            yield card


def length(n):
    return (
        bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else b"\x82" + n.to_bytes(2, "big")
    )


def tlv(t, b):
    return t.to_bytes(1 if t < 256 else 2, "big") + length(len(b)) + b


def fields(b):
    out = {}
    while b:
        t = b[0]
        i = 1
        if t & 31 == 31:
            t = (t << 8) | b[i]
            i += 1
        n = b[i]
        i += 1
        if n & 128:
            k = n & 127
            n = int.from_bytes(b[i : i + k], "big")
            i += k
        assert len(b) >= i + n
        out[t] = b[i : i + n]
        b = b[i + n :]
    return out


class Card:
    def __init__(self, wire, progress=None, report=None):
        self.wire = wire
        self.progress = progress
        self.report = report if report is not None else {}
        self.report.update(passed=False, checks=0, cases=[])
        self.checks = self.report["cases"]

    @contextmanager
    def step(self, label, ins, p1, p2):
        label = f"{label} [{ins:02x}/{p1:02x}/{p2:02x}]"
        entry = dict(case=label, passed=False)
        self.checks.append(entry)
        if self.progress:
            self.progress(label)
        start = time.monotonic()
        try:
            yield
            entry["passed"] = True
            self.report["checks"] += 1
        except Exception as error:
            entry["error"] = repr(error)
            self.report["failed_step"] = label
            raise
        finally:
            entry["milliseconds"] = round((time.monotonic() - start) * 1000, 2)

    def raw(self, label, ins, p1=0, p2=0, data=b"", cla=0, le=None, status=0x9000):
        """One APDU, deliberately without chaining or GET RESPONSE handling."""
        with self.step(label, ins, p1, p2):
            apdu = self.frame(ins, p1, p2, data, cla, le)
            answer, a, b = self.wire.transmit(apdu)
            assert a * 256 + b == status, (label, hex(a * 256 + b), hex(status))
            return bytes(answer)

    @staticmethod
    def frame(ins, p1, p2, data, cla, le):
        apdu = bytes([cla, ins, p1, p2])
        if data:
            apdu += bytes([len(data)]) + data
        if le is not None:
            apdu += bytes([le % 256])
        return apdu

    def cmd(self, label, ins, p1=0, p2=0, data=b"", le=256, cla=0, status=0x9000):
        with self.step(label, ins, p1, p2):
            chunks = [data[i : i + 193] for i in range(0, len(data), 193)] or [b""]
            answer = b""
            for i, chunk in enumerate(chunks):
                last = i == len(chunks) - 1
                apdu = self.frame(ins, p1, p2, chunk, cla if last else cla | 0x10, le if last else None)
                part, a, b = self.wire.transmit(apdu)
                sw = a * 256 + b
                if not last:
                    assert sw == 0x9000, (label, "chain", hex(sw))
                else:
                    answer = bytes(part)
            while sw >> 8 == 0x61:
                part, a, b = self.wire.transmit(bytes([0, 0xC0, 0, 0, 0]))
                answer += bytes(part)
                sw = a * 256 + b
            assert sw == status, (label, hex(sw), hex(status), answer.hex())
            return answer
