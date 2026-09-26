#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual UDP packets through the full Rust virtual card, independently verified."""
import hashlib
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData
from ctap_fixture import mixed_management

REBOOT = bytes.fromhex('ac1052ca95e569de69e02ebff333485f13f9b2da34c5a8a340526697a9ab2e0b394d8d04973c134005be1a0140bff6045bb26eb77a73eaa47813f6b49a7250dc')
INJECT = bytes.fromhex('991052ca95e569de69e02ebf')
UP = Path('/tmp/canokey-test-up')

class Card:
    def __init__(self, executable, image, reset=True, nfc=False):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 7112))
        self.socket.settimeout(3)
        self.process = subprocess.Popen([executable], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, CANOKEY_VIRT_LFS_ROOT=str(image),
                     CANOKEY_VIRT_RESET_STORAGE=str(int(reset)), CANOKEY_VIRT_NFC=str(int(nfc))))
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                assert selector.select(10), 'virtual card did not become ready'
            line = self.process.stdout.readline()
            if not line.startswith(b'Rust virtual HID ready'):
                raise AssertionError((line, self.process.stderr.read()))
        except BaseException:
            self.close()
            raise
        self.cid = 0xffffffff
        self.keepalives = []
        self.init()

    def send(self, cmd, data=b'', cid=None):
        cid = self.cid if cid is None else cid
        prefix = cid.to_bytes(4, 'big')
        self.socket.sendto((prefix + bytes([cmd]) + len(data).to_bytes(2, 'big') + data[:57]).ljust(64, b'\0'), ('127.0.0.1', 8111))
        for seq, start in enumerate(range(57, len(data), 59)):
            self.socket.sendto((prefix + bytes([seq]) + data[start:start+59]).ljust(64, b'\0'), ('127.0.0.1', 8111))

    def recv(self, command=None, cid=None):
        cid = self.cid if cid is None else cid
        end = time.monotonic() + 5
        while time.monotonic() < end:
            report = self.socket.recv(2048)
            assert len(report) == 64
            assert int.from_bytes(report[:4], 'big') == cid, report.hex()
            if report[4] == 0xbb:
                self.keepalives.append(report[7])
                continue
            assert command is None or report[4] == command, report.hex()
            total = int.from_bytes(report[5:7], 'big')
            data = report[7:7+total]
            sequence = 0
            while len(data) < total:
                report = self.socket.recv(2048)
                assert int.from_bytes(report[:4], 'big') == cid and report[4] == sequence
                data += report[5:5+min(59, total-len(data))]
                sequence += 1
            return data
        raise AssertionError('response timed out')

    def init(self):
        nonce = b'RustHID!'
        self.send(0x86, nonce)
        data = self.recv(0x86)
        assert data[:8] == nonce and len(data) == 17
        self.cid = int.from_bytes(data[8:12], 'big')
        assert self.cid not in (0, 0xffffffff)

    def ctap(self, command, params=None, status=0):
        self.send(0x90, bytes([command]) + (cbor.encode(params) if params is not None else b''))
        data = self.recv(0x90)
        assert data and data[0] == status, (command, data.hex(), status)
        result = cbor.decode(data[1:]) if len(data) > 1 else None
        if command == 10 and len(data) > 1:
            assert cbor.encode(result) == data[1:], "complete canonical management response"
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        out, err = self.process.communicate(timeout=5)
        self.socket.close()
        assert self.process.returncode == 143, (self.process.returncode, out, err)


def run(executable):
    old_up = UP.read_bytes() if UP.exists() else None
    try:
        with tempfile.TemporaryDirectory(prefix='rust-udp-') as directory:
            image = Path(directory)/'image'
            card = Card(executable, image)
            try:
                echo = bytes(range(256))*3
                card.send(0x81, echo)
                assert card.recv(0x81) == echo
                info = card.ctap(4)
                assert info[5] == 1024
                assert info[4]['credMgmt'] and info[4]['largeBlobs'] and info[11] == 4096
                card.ctap(6, {1: 1, 2: 2, 127: bytes(700)})
                def verify_attestation(result, challenge):
                    cert = x509.load_der_x509_certificate(result[3]['x5c'][0])
                    cert.public_key().verify(result[3]['sig'], result[2] + challenge, ec.ECDSA(hashes.SHA256()))
                mixed_management(card.ctap, verify_attestation)
                request_hash = hashlib.sha256(b'UDP credential test').digest()
                rp = 'rust-udp.example'
                made = card.ctap(1, {1: request_hash, 2: {'id': rp}, 3: {'id': b'udp-user'},
                                   4: [{'type': 'public-key', 'alg': -7}], 7: {'rk': True}})
                auth = AuthenticatorData(made[2])
                assert auth.is_user_present()
                cert = x509.load_der_x509_certificate(made[3]['x5c'][0])
                cert.public_key().verify(made[3]['sig'], made[2]+request_hash, ec.ECDSA(hashes.SHA256()))
                credential = {'type': 'public-key', 'id': auth.credential_data.credential_id}
                key = auth.credential_data.public_key
                assertion = {1: rp, 2: request_hash, 3: [credential], 5: {'up': False}}
                first = card.ctap(2, assertion)
                key.verify(first[2]+request_hash, first[3])
                counter = AuthenticatorData(first[2]).counter

                # One-shot read/write failure at the actual counter record.
                for operation in (0, 1):
                    card.socket.sendto(INJECT+bytes([operation, 0])+b'4f', ('127.0.0.1', 8111))
                    card.ctap(2, assertion, status=0x7f)
                    answer = card.ctap(2, assertion)
                    key.verify(answer[2]+request_hash, answer[3])
                    assert AuthenticatorData(answer[2]).counter > counter
                    counter = AuthenticatorData(answer[2]).counter

                # Runtime callback polls UDP while the applet waits for touch.
                UP.write_text('-1\n')
                card.send(0x90, b'\x0b')
                packet = card.socket.recv(64)
                assert packet[4] == 0xbb and packet[7] == 2
                card.send(0x91)
                assert card.recv(0x90) == b'\x2d'
                card.send(0x90, b'\x0b')
                assert card.socket.recv(64)[4] == 0xbb
                card.init() # same-channel INIT interrupts the live command
                assert card.ctap(4)[3] == info[3]

                # Reboot during a wait suppresses its response and preserves RK.
                card.send(0x90, b'\x0b')
                assert card.socket.recv(64)[4] == 0xbb
                card.socket.sendto(REBOOT, ('127.0.0.1', 8111))
                card.init()
                answer = card.ctap(2, assertion)
                key.verify(answer[2]+request_hash, answer[3])
                assert AuthenticatorData(answer[2]).counter > counter
                counter = AuthenticatorData(answer[2]).counter
            finally:
                card.close()

            # Keep storage on process restart: no re-fabrication, same key/counter.
            card = Card(executable, image, reset=False)
            try:
                answer = card.ctap(2, assertion)
                key.verify(answer[2]+request_hash, answer[3])
                assert AuthenticatorData(answer[2]).counter > counter
                found = card.ctap(2, {1: rp, 2: request_hash, 5: {'up': False}})
                assert found[1] == credential and found[4]['id'] == b'udp-user'
            finally:
                card.close()
            card = Card(executable, image, reset=False, nfc=True)
            try:
                UP.write_text('-1\n')
                assert card.ctap(0x0b) is None # simulated NFC policy, no touch
            finally:
                card.close()
    finally:
        if old_up is None:
            UP.unlink(missing_ok=True)
        else:
            UP.write_bytes(old_up)
    print('Rust UDP: real crypto, persistence, faults, cancellation, resync, reboot and NFC policy passed')

if __name__ == '__main__':
    run(sys.argv[1])
