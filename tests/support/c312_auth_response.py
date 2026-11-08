#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check response-source contracts through real transports and independent crypto.

Both runners execute unchanged production routing, applets and native crypto.
The C fixture lives in a separate pinned checkout. Opaque credential formats and
random signatures differ, so this suite asserts the same transport contract and
independently verifies each result; it does not claim equal response bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData
from fido2.ctap2.pin import PinProtocolV1

from c312_ccid import REVISION, build_c, digest
from c312_large_blob import hid_reports

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/integration"))
from card_test import Card
from ctap_fixture import provision, verify_credential

NFC_AID = bytes.fromhex("a0000006472f0001")
USB_AID = bytes.fromhex("f043414e4f464944")
ADMIN_AID = bytes.fromhex("f000000000")
SUCCESS = 0x9000
SOURCE_CHUNK = 250
BUFFER_CHUNK = 256
INF_BYTES = 29


class Nfc:
    def __init__(self, runner, rust, kind="nfc"):
        self.kind = kind
        self.directory = tempfile.TemporaryDirectory(prefix="c312-auth-response-")
        self.process = subprocess.Popen(
            [str(runner)] + (["--c312-nfc-wire"] if rust and kind == "nfc" else
                            ["--c312-usb-wire", "--auto-touch"] if rust else []),
            cwd=self.directory.name, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.lines = queue.Queue()
        self.diagnostics = []
        self.stderr = []
        self.trace = []
        self.apdus = []
        self.number = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.error_reader = threading.Thread(target=self._errors, daemon=True)
        self.error_reader.start()
        if not rust and kind != "nfc":
            self.process.stdin.write("USB\n")
            self.process.stdin.flush()

    def _read(self):
        for line in self.process.stdout:
            if line.startswith(("WIRE ", "HID ", "BULK ")):
                key, value = line.rstrip("\n").split(" ", 1)
                self.lines.put((key, value))
            else:
                self.diagnostics.append(line.rstrip())
        self.lines.put(None)

    def _errors(self):
        self.stderr.extend(self.process.stderr)

    def packet(self, frame):
        self.process.stdin.write("NFC " + (frame + b"\0\0").hex() + "\n")
        self.process.stdin.flush()
        line = self.lines.get(timeout=30)
        assert line is not None, (self.process.poll(), self.diagnostics, self.stderr)
        key, reply = line
        assert key == "WIRE", line
        result = bytes.fromhex(reply)
        self.trace.append(dict(packet=frame.hex(), response=reply))
        assert 0 < len(result) <= INF_BYTES + 1, result.hex()
        return result

    def transmit(self, frame):
        chunks = [frame[i:i + INF_BYTES] for i in range(0, len(frame), INF_BYTES)]
        for index, chunk in enumerate(chunks):
            more = index + 1 < len(chunks)
            pcb = self.number | (0x12 if more else 0x02)
            reply = self.packet(bytes([pcb]) + chunk)
            if more:
                assert reply == bytes([0xa2 | self.number]), reply.hex()
                self.number ^= 1
        data, segments = bytearray(), []
        while True:
            assert reply[0] in (0x02 | self.number, 0x12 | self.number), reply.hex()
            data.extend(reply[1:])
            segments.append(len(reply) - 1)
            if not reply[0] & 0x10:
                break
            self.number ^= 1
            reply = self.packet(bytes([0xa2 | self.number]))
        self.number ^= 1
        assert len(data) >= 2, data.hex()
        self.apdus.append(dict(request=frame.hex(), response=data.hex(), rf_lengths=segments))
        return bytes(data[:-2]), data[-2], data[-1]

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                code = self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise
        else:
            code = self.process.returncode
        self.reader.join(timeout=5)
        self.error_reader.join(timeout=5)
        self.directory.cleanup()
        assert code == 0, (code, self.diagnostics, self.stderr)


class Usb(Nfc):
    def __init__(self, runner, rust, kind):
        super().__init__(runner, rust, kind)
        self.sequence = 0
        self.selected = None
        assert self.ccid(0x62, b"")

    def event(self, command, data=b""):
        if command == "TICK":
            assert isinstance(data, int) and 0 <= data <= 0xffffffff
            encoded = str(data)
        else:
            encoded = data.hex()
        self.process.stdin.write(command + " " + encoded + "\n")
        self.process.stdin.flush()
        result = {}
        for key in ("WIRE", "HID", "BULK"):
            line = self.lines.get(timeout=30)
            assert line is not None, (self.process.poll(), self.diagnostics, self.stderr)
            observed, value = line
            assert observed == key and value != "STALL", line
            result[key] = bytes.fromhex(value)
        self.trace.append(dict(operation=command, data=encoded,
                               response={key: value.hex() for key, value in result.items()}))
        return result

    def tick(self, milliseconds):
        result = self.event("TICK", milliseconds)
        assert not any(result.values()), result

    def ccid(self, command, body):
        self.sequence = (self.sequence + 1) % 256
        header = bytes([command]) + len(body).to_bytes(4, "little") + bytes([0, self.sequence, 0, 0, 0])
        raw = header + body
        for offset in range(0, len(raw), 64):
            result = self.event("CCID", raw[offset:offset + 64])
            assert not result["HID"] and not result["WIRE"]
            if offset + 64 < len(raw):
                assert not result["BULK"]
        reply = result["BULK"]
        assert len(reply) >= 10 and reply[0] == 0x80
        assert int.from_bytes(reply[1:5], "little") == len(reply) - 10
        assert reply[5:10] == bytes([0, self.sequence, 0, 0x81, 0]), reply.hex()
        return reply[10:]

    def web(self, body):
        def setup(direction, request, length):
            return bytes([direction, request, 0, 0, 1, 0]) + length.to_bytes(2, "little")
        assert not self.event("SETUP", setup(0x41, 0, len(body)))["WIRE"]
        for offset in range(0, len(body), 16):
            assert not self.event("OUT", body[offset:offset + 16])["WIRE"]
        self.event("IN")
        # Fetch at most the complete short response. A terminating short packet
        # tells the host its actual size; no implementation response is predicted.
        reply = self.event("SETUP", setup(0xc1, 1, 258))["WIRE"]
        part = reply
        while len(part) == 16:
            part = self.event("IN")["WIRE"]
            reply += part
        self.event("IN")
        self.event("OUT")
        return reply

    def message(self, frame):
        # The public test client writes short ISO envelopes. Native MSG carries
        # the same fields in its fixed Lc16 header and optional Le16 trailer.
        cla, ins, p1, p2 = frame[:4]
        body, le = b"", b""
        if len(frame) == 5:
            le = (frame[4] or 256).to_bytes(2, "big")
        elif len(frame) > 5:
            extended = frame[4] == 0
            start = 7 if extended else 5
            n = int.from_bytes(frame[5:7], "big") if extended else frame[4]
            body = frame[start:start + n]
            if extended:
                assert len(frame) in (start + n, start + n + 2)
                le = frame[start + n:]
            elif len(frame) == 6 + n:
                le = (frame[-1] or 256).to_bytes(2, "big")
            else:
                assert len(frame) == 5 + n
        raw = bytes([cla, ins, p1, p2, 0]) + len(body).to_bytes(2, "big") + body + le
        reports = bytearray()
        for packet in hid_reports(0x83, raw):
            result = self.event("HID", packet)
            assert not result["WIRE"] and not result["BULK"]
            reports.extend(result["HID"])
        reply, total, sequence = bytearray(), None, 0
        for offset in range(0, len(reports), 64):
            packet = reports[offset:offset + 64]
            assert packet[:4] == bytes.fromhex("12345678")
            if packet[4] == 0xbb:
                assert packet[5:8] in (b"\0\x01\x01", b"\0\x01\x02")
                continue
            if total is None:
                assert packet[4] == 0x83, packet.hex()
                total = int.from_bytes(packet[5:7], "big")
                start = 7
            else:
                assert packet[4] == sequence
                sequence += 1
                start = 5
            reply.extend(packet[start:start + min(64 - start, total - len(reply))])
        assert total is not None and len(reply) == total
        return bytes(reply)

    def transmit(self, frame):
        # ADMIN provisioning always uses the real CCID endpoint. Native MSG
        # needs no SELECT; this also keeps the common client usable for setup.
        select = frame[1] == 0xa4
        if self.kind == "msg" and not select and self.selected == USB_AID:
            reply = self.message(frame)
        elif self.kind == "webusb":
            reply = self.web(frame)
        else:
            reply = self.ccid(0x6f, frame)
        if select:
            self.selected = frame[5:5 + frame[4]] if reply[-2:] == b"\x90\0" else None
        assert len(reply) >= 2, reply.hex()
        self.apdus.append(dict(request=frame.hex(), response=reply.hex()))
        return reply[:-2], reply[-2], reply[-1]


class Checks:
    def __init__(self, wire):
        self.wire = wire
        self.card = Card(wire)
        self.cases = []

    def select(self, aid=None):
        if aid is None:
            aid = NFC_AID if self.wire.kind == "nfc" else USB_AID
        reply = self.card.cmd("select", 0xa4, 4, data=aid)
        if aid in (NFC_AID, USB_AID):
            assert reply == b"U2F_V2"

    def certificate(self, data):
        self.select(ADMIN_AID)
        self.card.cmd("verify admin", 0x20, data=b"123456")
        self.card.cmd("certificate", 2, data=data)
        self.select()

    def command(self, label, ins, data=b"", cla=0, limit=256, source=False,
                extended=False, drain=True):
        start = len(self.wire.apdus)
        if extended or self.wire.kind == "msg":
            raw = bytes([cla, ins, 0, 0, 0]) + len(data).to_bytes(2, "big") + data
            raw += (limit % 65536).to_bytes(2, "big")
            part, hi, lo = self.wire.transmit(raw)
        else:
            chunks = [data[i:i + 193] for i in range(0, len(data), 193)] or [b""]
            for chunk in chunks[:-1]:
                assert self.wire.transmit(Card.frame(ins, 0, 0, chunk, cla | 0x10, None)) == (b"", 0x90, 0)
            part, hi, lo = self.wire.transmit(Card.frame(ins, 0, 0, chunks[-1], cla, limit))
        response = bytearray(part)
        windows = [(len(part), hi * 256 + lo, limit)]
        observations = [self.wire.apdus[-1]]
        while hi == 0x61 and drain:
            part, hi, lo = self.wire.transmit(bytes.fromhex("00c0000000"))
            response.extend(part)
            windows.append((len(part), hi * 256 + lo, 256))
            observations.append(self.wire.apdus[-1])
        total = len(response)
        if drain:
            assert hi * 256 + lo == SUCCESS, (label, response.hex(), hex(hi * 256 + lo))
            remaining = total
            for index, (length, status, le) in enumerate(windows):
                if self.wire.kind == "msg" and not source:
                    capacity = BUFFER_CHUNK
                elif extended and index == 0 or self.wire.kind == "msg" and remaining <= le:
                    capacity = le
                else:
                    capacity = min(le, SOURCE_CHUNK if source else BUFFER_CHUNK)
                assert length == min(remaining, capacity), (label, total, windows, capacity)
                remaining -= length
                expected = (0x6100 | min(remaining, 255)) if remaining else SUCCESS
                assert status == expected, (label, windows, hex(expected))
                # Extended FIDO suppresses internal status words but keeps the
                # source's250-byte boundaries in its RF frame sequence.
                internal = [length]
                if extended and index == 0:
                    internal = [min(SOURCE_CHUNK, length - offset)
                                for offset in range(0, length, SOURCE_CHUNK)] or [0]
                internal[-1] += 2
                rf = [min(INF_BYTES, segment - offset) for segment in internal
                      for offset in range(0, segment, INF_BYTES)]
                if self.wire.kind == "nfc":
                    assert observations[index]["rf_lengths"] == rf, (label, rf, observations[index])
            assert remaining == 0
        else:
            assert hi == 0x61 and len(part) == min(limit, SOURCE_CHUNK if source else BUFFER_CHUNK)
        self.cases.append(dict(case=label, passed=True, response_bytes=total, source=source,
                               windows=windows, apdus=self.wire.apdus[start:]))
        return bytes(response)

    def ctap(self, label, command, params=None, **kwargs):
        answer = self.command(label, 0x10, bytes([command]) + (cbor.encode(params) if params is not None else b""),
                              cla=0x80, **kwargs)
        assert answer[0] == 0, (label, answer.hex())
        return cbor.decode(answer[1:]) if len(answer) > 1 else {}


def suite(wire, small_pq=False):
    checks = Checks(wire)
    verify_attestation = provision(checks.card)
    checks.select()
    rp = "response.example"
    challenge = hashlib.sha256(b"C312 response source contract").digest()
    credentials = []
    for algorithm in [-7, -8, -49] + ([-48] if small_pq else []):
        params = {1: challenge, 2: {"id": rp}, 3: {"id": bytes([len(credentials) + 1]) * 64},
                  4: [{"type": "public-key", "alg": algorithm}]}
        result = checks.ctap(f"make-{algorithm}", 1, params, source=True)
        verify_attestation(result, challenge)
        auth = AuthenticatorData(result[2])
        assert auth.rp_id_hash == hashlib.sha256(rp.encode()).digest()
        descriptor = {"type": "public-key", "id": auth.credential_data.credential_id}
        short = checks.ctap(f"assert-{algorithm}-no-extensions", 2,
                            {1: rp, 2: challenge, 3: [descriptor]}, source=algorithm in (-49, -48))
        verify_credential(auth.credential_data.public_key, short[2] + challenge, short[3])
        assert short[1] == descriptor and AuthenticatorData(short[2]).counter > auth.counter
        resident = checks.ctap(f"make-{algorithm}-resident", 1,
                               params | {3: params[3] | {"name": "n" * 63, "displayName": "d" * 63},
                                         6: {"credBlob": b"b" * 32, "largeBlobKey": True}, 7: {"rk": True}},
                               source=True)
        verify_attestation(resident, challenge)
        auth = AuthenticatorData(resident[2])
        assert auth.extensions == {"credBlob": True}
        credentials.append((algorithm, auth.credential_data))
        descriptor = {"type": "public-key", "id": auth.credential_data.credential_id}
        # The classic response crosses256 with the resident user, credBlob and
        # largeBlobKey. The request uses its real stored credential, never a record injection.
        large = checks.ctap(f"assert-{algorithm}-extensions", 2,
                            {1: rp, 2: challenge, 3: [descriptor], 4: {"credBlob": True}}, source=True)
        assert len(cbor.encode(large)) + 1 > BUFFER_CHUNK
        verify_credential(auth.credential_data.public_key, large[2] + challenge, large[3])
        assert AuthenticatorData(large[2]).extensions == {"credBlob": b"b" * 32}

    # GetNextAssertion uses the same ordinary-CBOR source classification.
    by_id = {auth.credential_id: auth.public_key for _, auth in credentials}
    for index in range(len(credentials)):
        result = checks.ctap(f"discover-{index}", 2 if index == 0 else 8,
                             {1: rp, 2: challenge, 4: {"credBlob": True}} if index == 0 else None,
                             source=True)
        verify_credential(by_id[result[1]["id"]], result[2] + challenge, result[3])
        assert result.get(5) == (len(credentials) if index == 0 else None)

    # Exercise finite Le on a source-backed classic MC. Use the same resident
    # identity so this replaces one entry rather than exhausting the store.
    classic = {1: challenge, 2: {"id": rp}, 3: {"id": b"finite"},
               4: [{"type": "public-key", "alg": -7}]}
    for le in (1, 249, 250, 251, 255, 256):
        result = checks.ctap(f"make-Le-{le}", 1, classic, source=True, limit=le)
        verify_attestation(result, challenge)
    if wire.kind == "nfc":
        result = checks.ctap("make-extended-unlimited", 1, classic, source=True, extended=True, limit=65536)
        verify_attestation(result, challenge)
        result = checks.ctap("make-extended-finite", 1, classic, source=True, extended=True, limit=251)
        verify_attestation(result, challenge)
    elif wire.kind == "msg":
        result = checks.ctap("make-native-unlimited", 1, classic, source=True, limit=65536)
        verify_attestation(result, challenge)

    # Classical credential-management output is Prepared in Rust. Long user
    # metadata makes it exceed256; PQ enumeration shares the same command path.
    protocol = PinProtocolV1()
    public, secret = protocol.encapsulate(checks.ctap("key-agreement", 6, {1: 1, 2: 2})[1])
    pin = b"12345678"
    encrypted = protocol.encrypt(secret, pin.ljust(64, b"\0"))
    checks.ctap("set-pin", 6, {1: 1, 2: 3, 3: public,
                               4: protocol.authenticate(secret, encrypted), 5: encrypted})
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    token = protocol.decrypt(secret, checks.ctap("management-token", 6,
                                              {1: 1, 2: 9, 3: public, 6: hashed, 9: 4})[2])
    parameters = {1: hashlib.sha256(rp.encode()).digest()}
    begin = {1: 4, 2: parameters, 3: 1,
             4: protocol.authenticate(token, b"\x04" + cbor.encode(parameters))}
    enumerated = set()
    for index in range(len(credentials)):
        entry = checks.ctap(f"management-{index}", 10, begin if index == 0 else {1: 5}, source=True)
        assert len(cbor.encode(entry)) + 1 > BUFFER_CHUNK
        handle = entry[7]["id"]
        assert handle not in enumerated and entry[8] == by_id[handle]
        enumerated.add(handle)
        assert entry[6]["name"] == "n" * 63 and entry[6]["displayName"] == "d" * 63
        assert len(entry[6]["id"]) == 64
        assert entry.get(9) == (len(credentials) if index == 0 else None)
    assert enumerated == set(by_id)

    # Ed25519's fixed signature width lets the independent CBOR codec choose
    # user lengths that make an ordinary response exactly256 or257 bytes.
    handle_bytes = len(next(auth.credential_id for algorithm, auth in credentials if algorithm == -8))
    boundary_rp = "boundary.example"
    for target in (256, 257):
        length = next(n for n in range(1, 65) if len(cbor.encode({
            1: {"type": "public-key", "id": bytes(handle_bytes)}, 2: bytes(37),
            3: bytes(64), 4: {"id": bytes(n)}, 7: bytes(32)})) + 1 == target)
        # Setting a PIN above makes subsequent MC require a PIN authorization.
        # Obtain a token for MC/GA on this RP through the real PIN protocol.
        public, secret = protocol.encapsulate(checks.ctap(f"boundary-agreement-{target}", 6, {1: 1, 2: 2})[1])
        hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
        boundary_token = protocol.decrypt(secret, checks.ctap(f"boundary-token-{target}", 6,
            {1: 1, 2: 9, 3: public, 6: hashed, 9: 3, 10: boundary_rp})[2])
        auth_param = protocol.authenticate(boundary_token, challenge)
        result = checks.ctap(f"boundary-make-{target}", 1,
            {1: challenge, 2: {"id": boundary_rp}, 3: {"id": bytes([target % 256]) * length},
             4: [{"type": "public-key", "alg": -8}], 6: {"largeBlobKey": True}, 7: {"rk": True},
             8: auth_param, 9: 1}, source=True)
        verify_attestation(result, challenge)
        auth = AuthenticatorData(result[2])
        descriptor = {"type": "public-key", "id": auth.credential_data.credential_id}
        # A successful presence-authorized MC consumes MC/GA permissions.
        boundary_token = protocol.decrypt(secret, checks.ctap(f"boundary-assertion-token-{target}", 6,
            {1: 1, 2: 9, 3: public, 6: hashed, 9: 2, 10: boundary_rp})[2])
        auth_param = protocol.authenticate(boundary_token, challenge)
        result = checks.ctap(f"ordinary-response-{target}", 2,
                             {1: boundary_rp, 2: challenge, 3: [descriptor],
                              6: auth_param, 7: 1}, source=target > BUFFER_CHUNK)
        assert len(cbor.encode(result)) + 1 == target
        verify_credential(auth.credential_data.public_key, result[2] + challenge, result[3])

    if wire.kind == "msg":
        agreement = checks.ctap("buffered-native-ignores-small-Le", 6, {1: 1, 2: 2}, limit=1)
        protocol.encapsulate(agreement[1])

    if wire.kind != "nfc":
        return checks.cases

    # U2F REGISTER always uses a source, including an opaque provisioned
    # certificate that makes its total lie strictly between250 and256.
    # This tests the file transport contract, not X.509 certificate validity.
    private = ec.generate_private_key(ec.SECP256R1())
    checks.select(ADMIN_AID)
    checks.card.cmd("verify admin", 0x20, data=b"123456")
    checks.card.cmd("attestation key", 1, data=private.private_numbers().private_value.to_bytes(32, "big"))
    checks.card.cmd("opaque certificate", 2, data=b"c")
    checks.select()
    app = hashlib.sha256(rp.encode()).digest()

    def register(label):
        result = checks.command(label, 1, challenge + app, source=True)
        assert result[:2] == b"\x05\x04"
        handle = result[67:67 + result[66]]
        tail = result[67 + len(handle):]
        return result, handle, tail

    result, handle, tail = register("register-tiny-certificate")
    assert tail[:1] == b"c"
    private.public_key().verify(tail[1:], b"\0" + app + challenge + handle + result[1:66], ec.ECDSA(hashes.SHA256()))
    certificate = b"c" * (254 - (67 + len(handle)) - 71)
    assert certificate
    checks.certificate(certificate)
    result, handle, tail = register("register-source-below256")
    assert 250 < len(result) <= BUFFER_CHUNK, len(result)
    assert tail[:len(certificate)] == certificate
    private.public_key().verify(tail[len(certificate):], b"\0" + app + challenge + handle + result[1:66], ec.ECDSA(hashes.SHA256()))

    # Replacement closes a partially consumed certificate source.
    checks.command("register-abandoned", 1, challenge + app, source=True, limit=1, drain=False)
    checks.select()
    assert wire.transmit(bytes.fromhex("00c0000000")) == (b"", 0x69, 0x86)
    checks.cases.append(dict(case="replacement-closes-source", passed=True))
    return checks.cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-runner", type=Path, required=True)
    parser.add_argument("--c-repository", type=Path)
    parser.add_argument("--c-build", type=Path)
    parser.add_argument("--transport", choices=("nfc", "ccid", "webusb", "msg"), action="append")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runners = []
    if args.c_repository:
        assert args.c_build
        with args.output.with_suffix(".build.log").open("w") as log:
            runners.append(("c", build_c(args.c_repository, args.c_build, log)))
    runners.append(("rust", args.rust_runner.resolve()))
    report = dict(schema=1, scope="independently verified response-source contracts; not byte-equivalence",
                  reference_revision=REVISION if args.c_repository else None,
                  fixtures=[dict(path=str(path.relative_to(ROOT)), sha256=digest(path)) for path in (
                      Path(__file__), ROOT / "tests/support/c312_ccid.c",
                      ROOT / "tests/card/src/transport.rs",
                      ROOT / "tests/card/src/bin/usb_sessions/portable_webusb.rs")], results=[])
    try:
        for side, runner in runners:
            for kind in args.transport or ["nfc"]:
                wire = Nfc(runner, side == "rust") if kind == "nfc" else Usb(runner, side == "rust", kind)
                entry = dict(side=side, transport=kind, runner=str(runner), runner_sha256=digest(runner), passed=False)
                report["results"].append(entry)
                try:
                    entry["cases"] = suite(wire, small_pq=side == "rust")
                    entry["passed"] = True
                except Exception as error:
                    entry["error"] = repr(error)
                    raise
                finally:
                    try:
                        wire.close()
                    finally:
                        entry.update(trace=wire.trace, apdus=wire.apdus,
                                     diagnostics=wire.diagnostics, stderr=wire.stderr)
    finally:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({entry["side"] + "-" + entry["transport"]: len(entry["cases"]) for entry in report["results"]}))


if __name__ == "__main__":
    main()
