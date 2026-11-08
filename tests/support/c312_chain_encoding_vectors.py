#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate E68 mixed short/extended FIDO input-chain contracts from C rules."""
import argparse
import json
from pathlib import Path

from c312_select_vectors import (
    ADMIN_SELECT, ADMIN_VERIFY, FIDO_VERSION, GET_RESPONSE, NFC_AID,
    NO_RESPONSE, SUCCESS, USB_AID, VERSION, WRONG_LENGTH, Wire, select,
)
from c312_chain_control_vectors import LARGE_BLOB_GET, LARGE_BLOB_REPLY

ENCODINGS = ['short', 'case3e', 'case4e', 'case4e-le1']
UNKNOWN_REPLY = bytes.fromhex('f19000')
ENABLE_NDEF = bytes.fromhex('0040040100')
NDEF_AID = bytes.fromhex('d2760000850101')
# The CC file advertises0001 as this product's NDEF message EF identifier.
SELECT_MESSAGE = bytes.fromhex('00a4000c020001')


def command(cla, body, encoding, ins=0x10, offset=0):
    header = bytes([cla, ins]) + offset.to_bytes(2, 'big')
    if encoding == 'short':
        assert len(body) <= 255
        return header + bytes([len(body)]) + body
    # An empty extended body is Case2E, whose encoded Le is0000 or0001.
    if not body:
        return header + (bytes.fromhex('000001') if encoding == 'case4e-le1' else bytes(3))
    result = header + b'\0' + len(body).to_bytes(2, 'big') + body
    if encoding == 'case4e':
        result += bytes(2)  # Le0000 denotes65536, not zero response capacity.
    elif encoding == 'case4e-le1':
        result += bytes.fromhex('0001')
    return result


def finish(w, result, encoding):
    if encoding == 'case4e-le1' and len(result) > 3:
        payload = result[:-2]
        w.apdu(GET_RESPONSE, payload[1:] + SUCCESS)
    w.apdu(GET_RESPONSE, NO_RESPONSE)
    w.apdu(VERSION, FIDO_VERSION)
    # Recovery uses a fresh complete message, not SELECT-induced cleanup.
    w.apdu(command(0x80, LARGE_BLOB_GET, 'short'), LARGE_BLOB_REPLY)
    w.apdu(GET_RESPONSE, NO_RESPONSE)


def limited(result, encoding):
    payload = result[:-2]
    if encoding == 'case4e-le1' and len(payload) > 1:
        return payload[:1] + bytes([0x61, len(payload) - 1])
    return result


def generate():
    cases = []
    for transport in ['webusb', 'nfc']:
        aid = NFC_AID if transport == 'nfc' else USB_AID
        for first in ENCODINGS:
            for second in ENCODINGS:
                for chained in [False, True]:
                    for split in range(len(LARGE_BLOB_GET)):
                        w = Wire(transport)
                        w.apdu(select(aid), FIDO_VERSION)
                        if transport == 'nfc' and second != 'short':
                            # C discards this entire old semantic request before
                            # any inline extended MSG, including CLA90.
                            prefix = b'\xff'
                            body = LARGE_BLOB_GET[:split] if chained else LARGE_BLOB_GET
                            suffix = LARGE_BLOB_GET[split:]
                        else:
                            prefix = LARGE_BLOB_GET[:split]
                            body = LARGE_BLOB_GET[split:]
                            suffix = b''
                        w.apdu(command(0x90, prefix, first), SUCCESS)
                        terminal_encoding = 'short' if chained else second
                        w.apdu(command(0x90 if chained else 0x80, body, second),
                               SUCCESS if chained else limited(LARGE_BLOB_REPLY, second))
                        if chained:
                            w.apdu(command(0x80, suffix, 'short'), LARGE_BLOB_REPLY)
                        finish(w, LARGE_BLOB_REPLY, terminal_encoding)
                        cases.append(dict(
                            id=f'E68-{transport}-{first}-{second}-chained-{int(chained)}-split-{split}',
                            transport=transport, oracle_rows=['E21', 'E23', 'E68'],
                            preconditions='Fresh product and real FIDO SELECT. WebUSB continues matching input across encoding changes; every NFC extended MSG starts fresh, including CLA90 and Case2E. The literal default largeBlob byte80 proves complete semantic parsing. Le1 continuation and subsequent fresh commands prove response and input cleanup.',
                            steps=w.steps,
                        ))
        # Exercise the real288-byte WebUSB envelope and NFC inline/PKE boundary.
        # CLA90 is inline-only in NFC; an oversized chained envelope must still
        # reject rather than authorize the standalone CLA80 PKE route.
        for length in [255, 256, 279]:
            for second in ENCODINGS[1:]:
                for chained in [False, True]:
                    w = Wire(transport)
                    w.apdu(select(aid), FIDO_VERSION)
                    w.apdu(command(0x90, b'\xff' + bytes(254), 'short'), SUCCESS)
                    w.apdu(command(0x90 if chained else 0x80, b'\xff' + bytes(length - 1), second),
                           SUCCESS if chained else UNKNOWN_REPLY)
                    if chained:
                        w.apdu(command(0x80, b'', 'short'), UNKNOWN_REPLY)
                    finish(w, UNKNOWN_REPLY, 'short')
                    cases.append(dict(
                        id=f'E68-{transport}-inline-{length}-{second}-chained-{int(chained)}',
                        transport=transport, oracle_rows=['E11', 'E23', 'E68'],
                        preconditions='Real prior255-byte FIDO chain and extended inline fragment. Unknown CTAP commandff has a literalf1 status independent of ignored trailing bytes. Sizes255/256/279 cover short and inline boundaries without bypassing the transport.', steps=w.steps,
                    ))
        # Non-FIDO selected applets also admit inline extended continuation.
        # NDEF ignores continuation offsets and commits contiguous fragments.
        for first in ENCODINGS:
            for second in ENCODINGS:
                w = Wire(transport)
                w.apdu(ADMIN_SELECT, SUCCESS)
                w.apdu(ADMIN_VERIFY, SUCCESS)
                w.apdu(ENABLE_NDEF, SUCCESS)
                w.apdu(select(NDEF_AID), SUCCESS)
                w.apdu(SELECT_MESSAGE, SUCCESS)
                w.apdu(command(0x10, b'ab', first, 0xd6, 2), SUCCESS)
                w.apdu(command(0, b'cd', second, 0xd6, 20), SUCCESS)
                w.apdu(bytes.fromhex('00b0000204'), b'abcd' + SUCCESS)
                w.apdu(GET_RESPONSE, NO_RESPONSE)
                w.apdu(select(aid), FIDO_VERSION)
                w.apdu(VERSION, FIDO_VERSION)
                cases.append(dict(
                    id=f'E68-{transport}-ndef-{first}-{second}', transport=transport,
                    oracle_rows=['E23', 'E66', 'E68'],
                    preconditions='Fresh real Admin enables NDEF; actual EF selection and two UPDATE fragments use different encodings/offsets. Literal readbackabcd proves retained shared write cursor and semantic admission outside FIDO.', steps=w.steps,
                ))
    # CCID extended rejection precedes routing and preserves a short chain.
    for first in ENCODINGS[1:]:
        for second in ENCODINGS[1:]:
            w = Wire('ccid')
            w.apdu(select(USB_AID), FIDO_VERSION)
            w.apdu(command(0x90, LARGE_BLOB_GET[:3], first), WRONG_LENGTH)
            w.apdu(command(0x90, LARGE_BLOB_GET[:3], 'short'), SUCCESS)
            w.apdu(command(0x80, LARGE_BLOB_GET[3:], second), WRONG_LENGTH)
            w.apdu(command(0x80, LARGE_BLOB_GET[3:], 'short'), LARGE_BLOB_REPLY)
            finish(w, LARGE_BLOB_REPLY, 'short')
            cases.append(dict(
                id=f'E68-ccid-reject-{first}-{second}', transport='ccid',
                oracle_rows=['E01', 'E68'], preconditions='Short-only CCID rejects both extended fragments before Core. Retrying each fragment as short must complete the original valid largeBlob request.', steps=w.steps,
            ))
    return dict(schema=1, scope='Mixed short/extended input chains; WebUSB continuation versus NFC extended restart, inline bounds, NDEF write cursor, Le and short-only CCID guards.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
