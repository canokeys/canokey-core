#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate SELECT header/envelope contracts from pinned C dispatch (E66)."""
import argparse
import json
from pathlib import Path

from c312_select_vectors import (
    ADMIN_QUERY, ADMIN_SELECT, ADMIN_VERIFY, FIDO_VERSION, GET_RESPONSE,
    NFC_AID, NO_RESPONSE, NOT_FOUND, SUCCESS, USB_AID, VERSION, WRONG_LENGTH,
    WRONG_P2, Wire, select,
)

AIDS = {
    'admin': bytes.fromhex('f000000000'),
    'ndef': bytes.fromhex('d2760000850101'),
    'piv': bytes.fromhex('a000000308000010000100'),
    'openpgp': bytes.fromhex('d27600012401'),
}
CLA_NOT_SUPPORTED = bytes.fromhex('6e00')
INS_NOT_SUPPORTED = bytes.fromhex('6d00')
PIN_RETRIES = bytes.fromhex('63c3')
ENABLE_NDEF = bytes.fromhex('0040040100')
PIV_VERIFY = bytes.fromhex('0020008008313233343536ffff')
PIV_QUERY = bytes.fromhex('0020008000')
# PIV's19-byte selection response limited to Le1:61, then18 bytes remain.
PIV_SELECTED = bytes.fromhex('616112')
PGP_VERIFY = bytes.fromhex('00200083083132333435363738')
PGP_QUERY = bytes.fromhex('0020008300')
SELECT_CC = bytes.fromhex('00a4000c02e103')
READ_CC = bytes.fromhex('00b0000002')
# The CC EF starts with its15-byte length000F; the message EF starts0011.
CC_RESPONSE = bytes.fromhex('000f9000')


def stimuli(aid, extended):
    for cla in [0, 1, 0x10, 0x80, 0x90, 0xff]:
        for p1 in [0, 4, 0xff]:
            yield (f'cla-{cla:02x}-p1-{p1:02x}',
                   bytes([cla, 0xa4, p1, 0, len(aid)]) + aid,
                   False, False, len(aid), 256)
    if extended:
        for cla, p1 in [(0, 4), (0, 0), (0x10, 4), (0x80, 4)]:
            header = bytes([cla, 0xa4, p1, 0, 0])
            yield f'case2e-cla-{cla:02x}-p1-{p1:02x}', header + b'\0\0', True, False, 0, 65536
            for suffix in [b'\0', b'\0\0', b'\0\x01', b'\x01\0', b'\0\0\0']:
                yield (f'case4e-cla-{cla:02x}-p1-{p1:02x}-suffix-{suffix.hex()}',
                       header + len(aid).to_bytes(2, 'big') + aid + suffix,
                       True, len(suffix) != 2, len(aid), int.from_bytes(suffix, 'big') or 65536)


def outcome(prior, transport, request, extended, malformed, length, le):
    """C src/apdu.c discriminator precedes each applet's own CLA/INS checks."""
    cla, _, p1, _ = request[:4]
    if malformed:
        return WRONG_LENGTH, prior
    if cla == 0 and p1 == 4:
        if length:
            return (b'U2F_V2'[:le] + (bytes([0x61, 6 - le]) if le < 6 else SUCCESS)), 'fido'
        return NOT_FOUND, 'none' if prior == 'fido' and transport != 'nfc' else prior
    if prior == 'none':
        return NOT_FOUND, prior
    if prior == 'piv' and extended:
        return WRONG_LENGTH, prior
    if prior == 'ndef':
        return SUCCESS if p1 == 4 else WRONG_P2, prior
    if prior == 'fido':
        if cla == 0:
            return b'U2F_V2'[:le] + (bytes([0x61, 6 - le]) if le < 6 else SUCCESS), prior
        return {0x80: INS_NOT_SUPPORTED, 0x90: SUCCESS}.get(cla, CLA_NOT_SUPPORTED), prior
    return WRONG_P2 if cla == 0 else CLA_NOT_SUPPORTED, prior


def generate():
    cases = []
    for transport in ['ccid', 'webusb', 'nfc']:
        aid = NFC_AID if transport == 'nfc' else USB_AID
        for prior in ['none', 'fido', 'admin', 'ndef', 'piv', 'openpgp']:
            for label, request, extended, malformed, length, le in stimuli(aid, transport != 'ccid'):
                w = Wire(transport)
                w.apdu(ADMIN_SELECT, SUCCESS)
                w.apdu(ADMIN_VERIFY, SUCCESS)
                w.apdu(ENABLE_NDEF, SUCCESS)
                mask = 0x3f
                if prior == 'none':
                    # A disabled OpenPGP SELECT clears selection. FIDO remains
                    # enabled, so a subsequent valid FIDO SELECT can succeed.
                    mask &= ~(0x04 if transport == 'nfc' else 0x02)
                    w.apdu(bytes([0, 0x40, 6, mask, 0]), SUCCESS)
                w.apdu(bytes.fromhex('0042000000'), bytes([1, 0, 0, 1, 1, mask]) + SUCCESS)
                if prior == 'none':
                    w.apdu(select(AIDS['openpgp']), NOT_FOUND)
                elif prior == 'fido':
                    w.apdu(select(aid), FIDO_VERSION)
                elif prior != 'admin':
                    w.apdu(select(AIDS[prior]) + (b'\x01' if prior == 'piv' else b''),
                           PIV_SELECTED if prior == 'piv' else SUCCESS)
                    if prior == 'piv':
                        w.apdu(PIV_VERIFY, SUCCESS)
                    elif prior == 'openpgp':
                        w.apdu(PGP_VERIFY, SUCCESS)
                    else:
                        w.apdu(SELECT_CC, SUCCESS)
                        w.apdu(READ_CC, CC_RESPONSE)
                response, selected = outcome(prior, transport, request, extended, malformed, length, le)
                w.apdu(request, response)
                if prior == 'fido' and request[0] == 0x90:
                    # Intermediate proprietary fragments acknowledge first;
                    # the terminal80/A4 must reject INS without dispatching CBOR.
                    w.apdu(bytes([0x80, 0xa4, request[2], 0, 0]), INS_NOT_SUPPORTED)
                query = {'admin': ADMIN_QUERY, 'ndef': READ_CC, 'piv': PIV_QUERY,
                         'openpgp': PGP_QUERY}.get(prior, VERSION)
                if selected == 'fido':
                    expected = FIDO_VERSION if query == VERSION else INS_NOT_SUPPORTED
                elif selected == 'none':
                    expected = NOT_FOUND
                else:
                    expected = CC_RESPONSE if selected == 'ndef' else SUCCESS
                w.apdu(query, expected)
                w.apdu(GET_RESPONSE, NO_RESPONSE)
                w.apdu(ADMIN_SELECT, SUCCESS)
                w.apdu(ADMIN_QUERY, SUCCESS if selected == 'admin' else PIN_RETRIES)
                w.apdu(ADMIN_VERIFY, SUCCESS)
                w.apdu(bytes.fromhex('0040063f00'), SUCCESS)
                w.apdu(select(aid), FIDO_VERSION)
                w.apdu(VERSION, FIDO_VERSION)
                cases.append(dict(
                    id=f'E66-{transport}-{prior}-{label}', transport=transport,
                    oracle_rows=['E21', 'E23', 'E66'],
                    preconditions='Fresh product; real authenticated Admin configuration, SELECT and PIN grants. No injected routing state or physical timing claim.',
                    steps=w.steps,
                ))
        # The host's ordinary PUT DATA helper must use one short APDU even at
        # Lc255. C permits CLA10 only for certificate PUT DATA, not a URL.
        w = Wire(transport)
        w.apdu(select(AIDS['openpgp']), SUCCESS)
        w.apdu(PGP_VERIFY, SUCCESS)
        w.apdu(bytes.fromhex('10da5f5001') + b'X', CLA_NOT_SUPPORTED)
        w.apdu(PGP_QUERY, SUCCESS)
        w.apdu(bytes.fromhex('00da5f50ff') + b'U' * 255, SUCCESS)
        w.apdu(bytes.fromhex('00ca5f5001'), bytes.fromhex('5561fe'))
        w.apdu(bytes.fromhex('00c0000002'), bytes.fromhex('555561fc'))
        w.apdu(PGP_QUERY, SUCCESS)
        w.apdu(GET_RESPONSE, NO_RESPONSE)
        w.apdu(select(aid), FIDO_VERSION)
        cases.append(dict(id=f'E66-{transport}-openpgp-url-short255', transport=transport,
                          oracle_rows=['E66'], preconditions='Fresh product; actual PW3 verification. Reject chained URL, retain its grant, accept Lc255 short URL and verify literal response prefixes/abandonment.', steps=w.steps))
        w = Wire(transport)
        w.apdu(ADMIN_SELECT, SUCCESS)
        w.apdu(ADMIN_VERIFY, SUCCESS)
        w.apdu(ENABLE_NDEF, SUCCESS)
        w.apdu(select(AIDS['ndef']), SUCCESS)
        w.apdu(bytes.fromhex('01a4000c020001'), SUCCESS)
        w.apdu(bytes.fromhex('90d60002026162'), SUCCESS)
        # C continues at offset4, ignoring the second fragment's offset20.
        w.apdu(bytes.fromhex('81d60014026364'), SUCCESS)
        w.apdu(bytes.fromhex('90b0000204'), b'abcd' + SUCCESS)
        w.apdu(bytes.fromhex('ffb0000204'), b'abcd' + SUCCESS)
        w.apdu(bytes.fromhex('90ff000000'), INS_NOT_SUPPORTED)
        w.apdu(GET_RESPONSE, NO_RESPONSE)
        w.apdu(select(aid), FIDO_VERSION)
        cases.append(dict(id=f'E66-{transport}-ndef-ins-only-chain', transport=transport,
                          oracle_rows=['E66'], preconditions='Fresh product; actual Admin enables NDEF. Arbitrary CLA SELECT/READ/UPDATE; only UPDATE chains, ignoring continuation offset. Literal readback proves contiguous writes.', steps=w.steps))
    return dict(schema=1, scope='SELECT CLA/P1, Case2E and valid/malformed Case4E; retained Admin/PIV/OpenPGP grants, NDEF EF selection, FIDO chaining and recovery.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
