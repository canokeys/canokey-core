#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Load the real IFD shared library; no daemon, mock dispatcher or PC/SC hardware."""
import concurrent.futures
import ctypes as C
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData
from card_test import Card

DWORD = C.c_uint32 if sys.platform == 'darwin' else C.c_ulong
BYTE = C.c_ubyte
class PCI(C.Structure):
    _fields_ = [('Protocol', DWORD), ('Length', DWORD)]

class Driver:
    def __init__(self, library):
        self.lib = C.CDLL(library)
        self.lun = 0x10000 # reader number need not be zero; slot remains zero
        signatures = {
            'CreateChannel': [DWORD, DWORD], 'CreateChannelByName': [DWORD, C.c_char_p],
            'CloseChannel': [DWORD], 'ICCPresence': [DWORD],
            'GetCapabilities': [DWORD, DWORD, C.POINTER(DWORD), C.c_void_p],
            'SetProtocolParameters': [DWORD, DWORD, BYTE, BYTE, BYTE, BYTE],
            'PowerICC': [DWORD, DWORD, C.c_void_p, C.POINTER(DWORD)],
            'TransmitToICC': [DWORD, PCI, C.c_void_p, DWORD, C.c_void_p, C.POINTER(DWORD), C.POINTER(PCI)],
        }
        for name, args in signatures.items():
            function = getattr(self.lib, 'IFDH'+name)
            function.argtypes = args
            function.restype = C.c_long

    def capability(self, tag, capacity=64):
        buffer = (BYTE * (capacity+8))(*([0xa5]*(capacity+8)))
        length = DWORD(capacity)
        rc = self.lib.IFDHGetCapabilities(self.lun, tag, C.byref(length), buffer)
        assert bytes(buffer[capacity:]) == b'\xa5'*8
        return rc, bytes(buffer[:min(length.value, capacity)]), length.value

    def power(self, action, capacity=33):
        buffer = (BYTE * (capacity+8))(*([0xa5]*(capacity+8)))
        length = DWORD(capacity)
        rc = self.lib.IFDHPowerICC(self.lun, action, buffer, C.byref(length))
        assert bytes(buffer[capacity:]) == b'\xa5'*8
        return rc, bytes(buffer[:min(length.value, capacity)]), length.value

    def raw(self, command, capacity=8192):
        tx = C.create_string_buffer(bytes(command))
        rx = (BYTE * (capacity+8))(*([0xa5]*(capacity+8)))
        length, receive = DWORD(capacity), PCI()
        rc = self.lib.IFDHTransmitToICC(self.lun, PCI(2, C.sizeof(PCI)), tx, len(command),
                                       rx, C.byref(length), C.byref(receive))
        assert bytes(rx[capacity:]) == b'\xa5'*8
        assert receive.Protocol == 2 and receive.Length == C.sizeof(PCI)
        return rc, bytes(rx[:length.value]), length.value

    def transmit(self, data):
        rc, response, n = self.raw(data)
        assert rc == 0 and n >= 2, (rc, response.hex())
        return response[:-2], response[-2], response[-1]


def run(library):
    touch = Path('/tmp/canokey-test-up')
    saved_touch = touch.read_bytes() if touch.exists() else None
    try:
        with tempfile.TemporaryDirectory(prefix='rust-pcsc-') as directory:
            os.environ.update(CANOKEY_VIRT_LFS_ROOT=directory+'/image', CANOKEY_VIRT_RESET_STORAGE='1', CANOKEY_TEST_NFC='0')
            touch.write_text('0\n')
            d = Driver(library)
            assert d.lib.IFDHCreateChannel(d.lun, 0) == 0
            assert d.lib.IFDHCreateChannel(d.lun, 0) == 0
            assert d.lib.IFDHCreateChannel(d.lun+1, 0) == 617
            assert d.lib.IFDHICCPresence(d.lun) == 615
            assert d.capability(0x303) == (0, b'', 0) # not yet powered
            assert d.capability(0xfae) == (0, b'\x01', 1)
            assert d.capability(0xfad) == (0, b'\x01', 1)
            assert d.capability(0x999)[0] == 600
            assert d.capability(0xfb3, capacity=1)[0] == 618
            assert d.capability(0xfb3)[2] == C.sizeof(C.c_void_p)
            assert d.lib.IFDHSetProtocolParameters(d.lun, 1, 0, 0, 0, 0) == 607
            assert d.lib.IFDHSetProtocolParameters(d.lun, 2, 0, 0, 0, 0) == 0
            assert d.power(500, capacity=1)[0] == 618
            rc, atr, n = d.power(500)
            assert rc == 0 and n == 17 and atr.hex() == '3bf71100008131fe6543616e6f4b657999'
            assert d.capability(0x303) == (0, atr, n)
            assert d.capability(0x303, capacity=1)[0] == 618
            card = Card(d)
            # Legacy test-control reboot works before any applet selection.
            assert d.power(502)[0] == 0
            assert d.raw(bytes.fromhex('00ee0000041256abf0'))[:2] == (0, b'\x90\x00')
            admin = lambda: card.cmd('admin', 0xa4, 4, data=bytes.fromhex('f000000000'))
            verify = lambda: card.cmd('admin PIN', 0x20, data=b'123456')
            edit = lambda status=0x9000: card.cmd('slot write', 0x44, 1, data=bytes.fromhex('020361626300'), status=status)
            admin(); verify(); edit()
            assert d.power(501) == (0, b'', 0)
            assert d.raw(bytes.fromhex('0043000000'))[0] == 612
            assert d.power(500)[0] == 0
            admin(); edit(0x6982); verify()
            saved = card.cmd('slots', 0x43)
            assert saved[0] == 2
            d.lib.ck_platform_now.restype = C.c_uint32
            time.sleep(.025)
            before_reset = d.lib.ck_platform_now()
            assert d.power(502)[0] == 0
            assert d.lib.ck_platform_now() >= before_reset, 'slot reset restarted the power-on window'
            admin(); edit(0x6982)
            card.cmd('fido', 0xa4, 4, data=bytes.fromhex('a0000006472f0001'))

            # USB PC/SC returns a response chunk; NFC FIDO mode aggregates it.
            getinfo = bytes.fromhex('80100000010400')
            rc, response, n = d.raw(getinfo)
            assert rc == 0 and n == 258 and response[-2] == 0x61
            data = response[:-2]
            while response[-2] == 0x61:
                rc, response, n = d.raw(bytes.fromhex('00c0000000'))
                assert rc == 0
                data += response[:-2]
            assert data[0] == 0 and cbor.decode(data[1:])[4]['credMgmt']
            os.environ['CANOKEY_TEST_NFC'] = '1'
            rc, aggregate, n = d.raw(bytes.fromhex('80108000010400'))
            assert rc == 0 and aggregate == data+b'\x90\x00' and n > 258
            assert d.raw(getinfo, capacity=257)[0] == 618
            assert d.raw(bytes.fromhex('00c0000000'))[1] == b'\x69\x86'
            assert d.raw(bytes(1034))[0] == 618
            assert d.raw(b'\x00')[1] == b'\x67\x00'
            assert d.raw(getinfo, capacity=1)[0] == 618
            assert d.raw(bytes.fromhex('00030000000000'))[1] == b'U2F_V2\x90\x00'

            def ctap(command, params=None, expected=0):
                payload = bytes([command]) + (cbor.encode(params) if params is not None else b'')
                apdu = b'\x80\x10\x80\x00\x00'+len(payload).to_bytes(2,'big')+payload
                rc, result, _ = d.raw(apdu)
                assert rc == 0 and result[-2:] == b'\x90\x00' and result[0] == expected, (rc, result.hex())
                return cbor.decode(result[1:-2]) if len(result) > 3 else None
            ctap(6, {1: 1, 2: 2, 127: bytes(700)}) # full standalone extended input
            digest = hashlib.sha256(b'IFD boundary').digest()
            rp = 'rust-pcsc.example'
            made = ctap(1, {1: digest, 2: {'id': rp}, 3: {'id': b'pcsc'},
                             4: [{'type': 'public-key', 'alg': -7}], 7: {'rk': True}})
            auth = AuthenticatorData(made[2])
            key = auth.credential_data.public_key
            x509.load_der_x509_certificate(made[3]['x5c'][0]).public_key().verify(made[3]['sig'], made[2]+digest, ec.ECDSA(hashes.SHA256()))
            request = {1: rp, 2: digest, 5: {'up': False}}
            answer = ctap(2, request)
            key.verify(answer[2]+digest, answer[3])
            counter = AuthenticatorData(answer[2]).counter
            for operation in [0, 1]:
                card.cmd('inject counter failure', 0xef, operation, data=b'4f')
                ctap(2, request, expected=0x7f)
                answer = ctap(2, request)
                key.verify(answer[2]+digest, answer[3])
                assert AuthenticatorData(answer[2]).counter > counter
                counter = AuthenticatorData(answer[2]).counter
            card.cmd('magic reboot', 0xee, data=bytes.fromhex('1256abf0'))
            answer = ctap(2, request)
            assert AuthenticatorData(answer[2]).counter > counter

            # Real PC/SC callers may use a different daemon thread per call.
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as threads:
                replies = list(threads.map(lambda _: d.raw(bytes.fromhex('00030000000000'))[1], range(40)))
            assert replies == [b'U2F_V2\x90\x00']*40

            # USB U2F polling advances raw presence between serialized calls.
            os.environ['CANOKEY_TEST_NFC'] = '0'
            challenge, app = hashlib.sha256(b'challenge').digest(), hashlib.sha256(b'app').digest()
            register = bytes.fromhex('00010000000040')+challenge+app
            rc, reply, _ = d.raw(register)
            assert rc == 0 and reply == b'\x69\x85'
            for _ in range(80):
                time.sleep(.025)
                rc, reply, _ = d.raw(register)
                assert rc == 0
                if reply != b'\x69\x85': break
            else:
                raise AssertionError('U2F polling never accepted a fresh gesture')
            registration = reply[:-2]
            while reply[-2] == 0x61:
                rc, reply, _ = d.raw(bytes.fromhex('00c0000000'))
                assert rc == 0
                registration += reply[:-2]
            assert reply[-2:] == b'\x90\x00' and registration[:2] == b'\x05\x04'
            length = registration[66]
            handle, tail = registration[67:67+length], registration[67+length:]
            width = tail[1] & 127
            cert_len = 2+width+int.from_bytes(tail[2:2+width], 'big')
            x509.load_der_x509_certificate(tail[:cert_len]).public_key().verify(tail[cert_len:], b'\0'+app+challenge+handle+registration[1:66], ec.ECDSA(hashes.SHA256()))

            assert d.lib.IFDHCloseChannel(d.lun) == 0
            assert d.lib.IFDHICCPresence(d.lun) == 616
            os.environ['CANOKEY_VIRT_RESET_STORAGE'] = '0'
            os.environ['CANOKEY_TEST_NFC'] = '1'
            assert d.lib.IFDHCreateChannelByName(d.lun, b'virtual') == 0
            assert d.power(500)[0] == 0
            answer = ctap(2, request)
            key.verify(answer[2]+digest, answer[3])
            admin(); edit(0x6982); verify()
            assert card.cmd('retained slots', 0x43) == saved
            assert d.lib.IFDHCloseChannel(d.lun) == 0
    finally:
        if saved_touch is None: touch.unlink(missing_ok=True)
        else: touch.write_bytes(saved_touch)
    print('Rust PC/SC: ABI bounds, power/auth, APDU/extended/NFC, persistence, faults, threads and U2F passed')

if __name__ == '__main__':
    run(sys.argv[1])
