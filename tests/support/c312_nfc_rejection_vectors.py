#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate E69 NFC large-envelope rejection/retention contracts from C rules."""
import argparse
import json
from pathlib import Path

from c312_select_vectors import (
    ADMIN_SELECT, ADMIN_VERIFY, FIDO_VERSION, GET_RESPONSE, NFC_AID,
    NO_RESPONSE, NOT_FOUND, SUCCESS, VERSION, WRONG_LENGTH, WRONG_P2, Wire, select,
)
from c312_chain_control_vectors import LARGE_BLOB_GET, LARGE_BLOB_REPLY

HEADERS = [
    '90100000', '80110000', '00c00000', '80c0ffff', '00a404ff',
    '00d60000', '80100100', '80100001', '80100000', '80108000',
]
FORMS = ['case3e', 'case4e', 'case4e-le1', 'tail1', 'tail3', 'truncated']
PRIORS = ['chain5', 'chain6', 'info', 'ndef', 'openpgp']
UNKNOWN_REPLY = bytes.fromhex('f19000')
TOO_LARGE_REPLY = bytes.fromhex('399000')
# GetInfo first returns the CTAP success byte; the next byte is CBOR map(21).
INFO_FIRST = bytes.fromhex('0061ff')
INFO_NEXT = bytes.fromhex('b561ff')
PGP_AID = bytes.fromhex('d27600012401')
PGP_VERIFY = bytes.fromhex('00200083083132333435363738')


def command(header, length, form):
    result = header + b'\0' + length.to_bytes(2, 'big') + b'\xff' * length
    if form == 'case4e':
        return result + bytes(2)
    if form == 'case4e-le1':
        return result + bytes.fromhex('0001')
    if form == 'tail1':
        return result + b'\0'
    if form == 'tail3':
        return result + bytes(3)
    if form == 'truncated':
        return result[:-1]
    return result


def begin(prior):
    w = Wire('nfc')
    if prior == 'ndef':
        w.apdu(ADMIN_SELECT, SUCCESS)
        w.apdu(ADMIN_VERIFY, SUCCESS)
        w.apdu(bytes.fromhex('0040040100'), SUCCESS)
        w.apdu(select(bytes.fromhex('d2760000850101')), SUCCESS)
        # This product's CC advertises message EF0001.
        w.apdu(bytes.fromhex('00a4000c020001'), SUCCESS)
        w.apdu(bytes.fromhex('10d60002026162'), SUCCESS)
    elif prior == 'openpgp':
        w.apdu(select(PGP_AID), SUCCESS)
        w.apdu(PGP_VERIFY, SUCCESS)
        w.apdu(bytes.fromhex('10da7f21026162'), SUCCESS)
    else:
        w.apdu(select(NFC_AID), FIDO_VERSION)
        if prior.startswith('chain'):
            prefix = LARGE_BLOB_GET[:int(prior[-1])]
            w.apdu(bytes.fromhex('90100000') + bytes([len(prefix)]) + prefix, SUCCESS)
        else:
            w.apdu(bytes.fromhex('80100000010401'), INFO_FIRST)
    return w


def expectation(prior, header, length, malformed):
    fido = prior not in ['ndef', 'openpgp']
    message = header[:2] == bytes.fromhex('8010')
    poll = header[0] in [0, 0x80] and header[1] == 0xc0
    status = WRONG_LENGTH
    if not malformed and message:
        if not fido:
            status = NOT_FOUND
        elif header[2] & 0x7f or header[3]:
            status = WRONG_P2
        elif length > 1296:
            status = TOO_LARGE_REPLY
        else:
            status = UNKNOWN_REPLY
    return status, fido and (malformed or message), poll and not malformed


def end(w, prior, cancelled, retained_output):
    if prior.startswith('chain'):
        suffix = LARGE_BLOB_GET[int(prior[-1]):]
        # After cancellation, empty APDU is6700 and command00 is unhandledf1.
        result = (UNKNOWN_REPLY if suffix else WRONG_LENGTH) if cancelled else LARGE_BLOB_REPLY
        w.apdu(bytes.fromhex('80100000') + bytes([len(suffix)]) + suffix, result)
        w.apdu(GET_RESPONSE, NO_RESPONSE)
        w.apdu(VERSION, FIDO_VERSION)
    elif prior == 'info':
        w.apdu(bytes.fromhex('00c0000001'), INFO_NEXT if retained_output else NO_RESPONSE)
    elif prior == 'ndef':
        # The second offset20 must not replace the retained write cursor4.
        w.apdu(bytes.fromhex('00d60014026364'), SUCCESS)
        w.apdu(bytes.fromhex('00b0000204'), b'abcd' + SUCCESS)
    else:
        w.apdu(bytes.fromhex('00da7f21026364'), SUCCESS)
        w.apdu(bytes.fromhex('00ca7f2104'), b'abcd' + SUCCESS)
        # Transport rejection must also preserve the actual PW3 grant.
        w.apdu(bytes.fromhex('0020008300'), SUCCESS)
    w.apdu(select(NFC_AID), FIDO_VERSION)
    w.apdu(bytes.fromhex('8010000006') + LARGE_BLOB_GET, LARGE_BLOB_REPLY)
    w.apdu(GET_RESPONSE, NO_RESPONSE)


def fragmented(w, request, response, first, repeat):
    chunks = [request[:first]] + [request[i:i + 29] for i in range(first, len(request), 29)]
    for index, chunk in enumerate(chunks):
        more = index + 1 < len(chunks)
        packet = bytes([(0x12 if more else 0x02) | w.number]) + chunk + bytes(2)
        reply = bytes([0xa2 | w.number]) if more else bytes([0x02 | w.number]) + response
        w.steps.append(dict(packet=packet.hex(), expected=reply.hex()))
        if more and repeat:
            w.steps.append(dict(packet=packet.hex(), expected=reply.hex()))
        w.number ^= 1


def generate():
    cases = []
    for prior in PRIORS:
        for encoded in HEADERS:
            header = bytes.fromhex(encoded)
            for length in [280, 1296, 1297]:
                for form in FORMS:
                    malformed = form in ['tail1', 'tail3', 'truncated']
                    status, cancelled, retained = expectation(prior, header, length, malformed)
                    w = begin(prior)
                    w.apdu(command(header, length, form), status)
                    end(w, prior, cancelled, retained)
                    cases.append(dict(
                        id=f'E69-{prior}-{encoded}-lc-{length}-{form}', transport='nfc',
                        oracle_rows=['E11', 'E21', 'E23', 'E69'],
                        preconditions='Fresh real applet/config/PIN context. Pinned C NFC prefix/discard and final-malformed rules supply status and retention; no injected applet state. Default largeBlob byte80, GetInfo map21, NDEF contiguous readback and OpenPGP certificate/PW3 prove input/output/authorization lifetime. Later fresh commands prove recovery.',
                        steps=w.steps,
                    ))
    # Split the envelope at every header/body boundary and repeat all chained
    # RF blocks. Core cleanup/staging must run once per accepted byte stream.
    for prior, encoded in [('chain5', '90100000'), ('chain6', '80100000'),
                           ('info', '80c0ffff'), ('ndef', '80100000'),
                           ('openpgp', '00100000')]:
        header = bytes.fromhex(encoded)
        for first in range(1, 9):
            for repeat in [False, True]:
                status, cancelled, retained = expectation(prior, header, 280, False)
                w = begin(prior)
                fragmented(w, command(header, 280, 'case4e'), status, first, repeat)
                end(w, prior, cancelled, retained)
                cases.append(dict(
                    id=f'E69-{prior}-{encoded}-first-{first}-repeat-{int(repeat)}', transport='nfc',
                    oracle_rows=['E11', 'E69'],
                    preconditions='Actual pending applet state and accepted/refused extended280-byte request. First RF INF ends at each envelope header/body boundary; repeated RF chains must not repeat prefix cleanup or PKE writes. Literal continuation/readback and fresh commands prove retained state and recovery.',
                    steps=w.steps,
                ))
    return dict(schema=1, scope='NFC large rejected/malformed/accepted envelopes: FIDO input, GetInfo response, NDEF/OpenPGP cursors, PIN grants, boundaries, retries and recovery.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
