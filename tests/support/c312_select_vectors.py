#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate literal SELECT contracts from the pinned C routing rules (E64)."""
import argparse
import json
from pathlib import Path

USB_AID = bytes.fromhex('f043414e4f464944')
NFC_AID = bytes.fromhex('a0000006472f0001')
ADMIN_SELECT = bytes.fromhex('00a4040005f000000000')
ADMIN_VERIFY = bytes.fromhex('0020000006313233343536')
ADMIN_QUERY = bytes.fromhex('0020000000')
VERSION = bytes.fromhex('0003000000')
GET_RESPONSE = bytes.fromhex('00c0000000')
SUCCESS = bytes.fromhex('9000')
NOT_FOUND = bytes.fromhex('6a82')
WRONG_P2 = bytes.fromhex('6a86')
WRONG_LENGTH = bytes.fromhex('6700')
NO_RESPONSE = bytes.fromhex('6986')
FIDO_VERSION = b'U2F_V2' + SUCCESS
ATR = bytes.fromhex('3bf71100008131fe6543616e6f6b657999')
CCID_ERROR = 0x81


def select(aid, p2=0, extended=False):
    header = bytes([0, 0xa4, 4, p2])
    if extended:
        return header + b'\0' + len(aid).to_bytes(2, 'big') + aid
    return header + (bytes([len(aid)]) + aid if aid else b'')


class Wire:
    def __init__(self, transport):
        self.transport, self.steps, self.sequence, self.number = transport, [], 0, 0
        if transport == 'ccid':
            self.ccid(0x62, b'', ATR)

    def ccid(self, command, body, response):
        self.sequence += 1
        packet = bytes([command]) + len(body).to_bytes(4, 'little') + bytes([0, self.sequence, 0, 0, 0]) + body
        reply = bytes([0x80]) + len(response).to_bytes(4, 'little') + bytes([0, self.sequence, 0, CCID_ERROR, 0]) + response
        for offset in range(0, len(packet), 64):
            self.steps.append(dict(packet=packet[offset:offset + 64].hex(),
                                   expected=reply.hex() if offset + 64 >= len(packet) else ''))

    def apdu(self, request, response):
        if self.transport == 'ccid':
            self.ccid(0x6f, request, response)
        elif self.transport == 'webusb':
            setup = bytes.fromhex('410000000100') + len(request).to_bytes(2, 'little')
            self.steps.append(dict(setup=setup.hex(), expected=''))
            for offset in range(0, len(request), 16):
                self.steps.append(dict(out=request[offset:offset + 16].hex(), expected=''))
            self.steps.extend([dict(**{'in': True}, expected=''),
                               dict(setup='c101000001000001', expected=response.hex()),
                               dict(**{'in': True}, expected=''), dict(out='', expected='')])
        else:
            chunks = [request[i:i + 29] for i in range(0, len(request), 29)]
            for i, chunk in enumerate(chunks):
                more = i + 1 < len(chunks)
                frame = bytes([(0x12 if more else 0x02) | self.number]) + chunk + b'\0\0'
                reply = bytes([0xa2 | self.number]) if more else bytes([0x02 | self.number]) + response
                self.steps.append(dict(packet=frame.hex(), expected=reply.hex()))
                self.number ^= 1


def stimuli(aid, opposite, extended):
    for length in [0, 1, 7, 8, 9, 15, 16, 17, 18, 255]:
        candidate = (aid + b'\x5a' * max(0, length - len(aid)))[:length]
        yield f'length-{length}', select(candidate), FIDO_VERSION if length == len(aid) else NOT_FOUND, False
    yield 'opposite-transport-aid', select(opposite), NOT_FOUND, False
    for position in range(len(aid)):
        candidate = bytearray(aid)
        candidate[position] ^= 1
        yield f'mutate-byte-{position}', select(candidate), NOT_FOUND, False
    for p2 in [1, 4, 0x0c, 0xff]:
        for length in [8, 17]:
            candidate = aid + b'\x5a' * (length - len(aid))
            yield f'p2-{p2:02x}-length-{length}', select(candidate, p2), WRONG_P2, False
    for p2 in [0, 0xff]:
        # Complete transport message, but Lc17 supplies only16 bytes: the
        # envelope fails before routing and must preserve prior selection.
        yield f'truncated-lc17-p2-{p2:02x}', bytes([0, 0xa4, 4, p2, 17]) + b'\x5a' * 16, WRONG_LENGTH, True
    if extended:
        for length in [17, 279]:
            for p2 in [0, 0xff]:
                yield f'extended-{length}-p2-{p2:02x}', select(aid + b'\x5a' * (length - len(aid)), p2, True), WRONG_P2 if p2 else NOT_FOUND, False


def generate():
    result = []
    for transport in ['ccid', 'webusb', 'nfc']:
        aid, opposite = (NFC_AID, USB_AID) if transport == 'nfc' else (USB_AID, NFC_AID)
        for prior in ['none', 'fido', 'admin-pin']:
            for label, request, response, malformed in stimuli(aid, opposite, transport != 'ccid'):
                wire = Wire(transport)
                if prior == 'fido':
                    wire.apdu(select(aid), FIDO_VERSION)
                elif prior == 'admin-pin':
                    wire.apdu(ADMIN_SELECT, SUCCESS)
                    wire.apdu(ADMIN_VERIFY, SUCCESS)
                wire.apdu(request, response)
                if response == FIDO_VERSION:
                    wire.apdu(VERSION, FIDO_VERSION)
                elif prior == 'admin-pin':
                    wire.apdu(ADMIN_QUERY, SUCCESS)
                else:
                    retained = prior == 'fido' and (transport == 'nfc' or malformed)
                    wire.apdu(VERSION, FIDO_VERSION if retained else NOT_FOUND)
                wire.apdu(GET_RESPONSE, NO_RESPONSE)
                wire.apdu(select(aid), FIDO_VERSION)
                wire.apdu(VERSION, FIDO_VERSION)
                result.append(dict(id=f'E64-{transport}-{prior}-{label}', transport=transport,
                                   oracle_rows=['E21', 'E23', 'E64'],
                                   preconditions='Fresh authenticator; actual transport/applets. Prior selection is absent, FIDO, or authenticated Admin. Rejected USB SELECT revokes only FIDO; malformed envelopes never enter routing. No physical timing claim.',
                                   steps=wire.steps))
    return dict(schema=1, scope='Literal SELECT AID/length/P2, rejection ordering, selected-context/grant retention and recovery across CCID/WebUSB/NFC.', cases=result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
