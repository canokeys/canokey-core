#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate E67 pending FIDO input-chain contracts from pinned C dispatch rules."""
import argparse
import json
from pathlib import Path

from c312_select_vectors import (
    ADMIN_SELECT, ADMIN_VERIFY, FIDO_VERSION, GET_RESPONSE, NFC_AID,
    NOT_FOUND, NO_RESPONSE, SUCCESS, USB_AID, VERSION, WRONG_LENGTH,
    WRONG_P2, Wire, select,
)

# CTAP largeBlob get one byte at offset zero: the default serialized array is80.
LARGE_BLOB_GET = bytes.fromhex('0ca201010300')
LARGE_BLOB_REPLY = bytes.fromhex('00a1014180') + SUCCESS
UNKNOWN_COMMAND = bytes.fromhex('ff')
UNKNOWN_REPLY = bytes.fromhex('f1') + SUCCESS
# key2 is set, whose value must be a byte string; integer0 is an unexpected type.
WRONG_BLOB_TYPE = bytes.fromhex('0ca201010200')
WRONG_TYPE_REPLY = bytes.fromhex('11') + SUCCESS
TERMINAL = bytes.fromhex('8010000000')
DISABLE_NDEF = bytes.fromhex('0040040000')
NDEF_AID = bytes.fromhex('d2760000850101')
INS_NOT_SUPPORTED = bytes.fromhex('6d00')


def interruptions(aid):
    # Each disposition describes the C input chain after the interruption.
    # USB malformed/extended CCID envelopes never enter routing; NFC malformed
    # envelopes explicitly reset input. Rejected USB SELECT revokes FIDO.
    yield 'none', None, None, 'retain'
    for name, command in [
        ('get-response', GET_RESPONSE),
        ('get-response-case1', bytes.fromhex('00c00000')),
        ('get-response-proprietary-body', bytes.fromhex('80c0ffff01aa')),
    ]:
        yield name, command, NO_RESPONSE, 'retain'
    for name, command, status in [
        ('unknown-select', select(b'X'), NOT_FOUND),
        ('invalid-p2-select', select(aid, 0xff), WRONG_P2),
        ('disabled-ndef-select', select(NDEF_AID), NOT_FOUND),
    ]:
        yield name, command, status, 'reject-select'
    yield 'same-fido-select', select(aid), FIDO_VERSION, 'reset'
    yield 'admin-select', ADMIN_SELECT, SUCCESS, 'admin'
    yield ('unsupported-command', bytes.fromhex('0040060000'),
           INS_NOT_SUPPORTED, 'reset')
    for name, command in [
        ('malformed-get-response', bytes.fromhex('00c0000002aa')),
        ('malformed-select', bytes.fromhex('00a4040011') + b'X' * 16),
        ('malformed-extended-select', select(aid, extended=True) + b'\0'),
    ]:
        yield name, command, WRONG_LENGTH, 'malformed'
    for name, command, status, disposition in [
        ('extended-get-response', bytes.fromhex('00c00000000000'), NO_RESPONSE, 'retain'),
        ('extended-get-response-body', bytes.fromhex('80c0ffff000001aa0000'), NO_RESPONSE, 'retain'),
        ('extended-unknown-select', select(b'X', extended=True), NOT_FOUND, 'reject-select'),
        ('extended-invalid-p2-select', select(aid, 0xff, True), WRONG_P2, 'reject-select'),
        ('extended-disabled-ndef-select', select(NDEF_AID, extended=True), NOT_FOUND, 'reject-select'),
        ('extended-same-fido-select', select(aid, extended=True), FIDO_VERSION, 'reset'),
    ]:
        yield name, command, status, 'extended-' + disposition


def generate():
    cases = []
    payloads = [
        ('large-blob', LARGE_BLOB_GET, LARGE_BLOB_REPLY),
        ('unknown', UNKNOWN_COMMAND, UNKNOWN_REPLY),
        ('wrong-type', WRONG_BLOB_TYPE, WRONG_TYPE_REPLY),
        ('empty', b'', WRONG_LENGTH),
    ]
    for transport in ['ccid', 'webusb', 'nfc']:
        aid = NFC_AID if transport == 'nfc' else USB_AID
        for payload_name, payload, result in payloads:
            # Every nonempty payload also starts with an empty ISO fragment;
            # schema state must survive GET RESPONSE at each split schedule.
            for split in sorted({0, len(payload) // 2, len(payload)}):
                for name, command, status, disposition in interruptions(aid):
                    w = Wire(transport)
                    w.apdu(ADMIN_SELECT, SUCCESS)
                    w.apdu(ADMIN_VERIFY, SUCCESS)
                    w.apdu(DISABLE_NDEF, SUCCESS)
                    w.apdu(select(aid), FIDO_VERSION)
                    for fragment in [payload[:split], payload[split:]]:
                        header = bytes.fromhex('90100000')
                        w.apdu(header + bytes([len(fragment)]) + fragment, SUCCESS)
                    if disposition.startswith('extended-'):
                        if transport == 'ccid':
                            disposition, status = 'retain', WRONG_LENGTH
                        else:
                            disposition = disposition.removeprefix('extended-')
                    if command is not None:
                        w.apdu(command, status)
                    if disposition == 'reject-select':
                        disposition = 'retain' if transport == 'nfc' else 'unselected'
                    elif disposition == 'malformed':
                        disposition = 'reset' if transport == 'nfc' else 'retain'
                    terminal = {
                        'retain': result, 'reset': WRONG_LENGTH,
                        'unselected': NOT_FOUND, 'admin': bytes.fromhex('6e00'),
                    }[disposition]
                    w.apdu(TERMINAL, terminal)
                    w.apdu(GET_RESPONSE, NO_RESPONSE)
                    w.apdu(VERSION, {
                        'unselected': NOT_FOUND, 'admin': bytes.fromhex('6982'),
                    }.get(disposition, FIDO_VERSION))
                    w.apdu(select(aid), FIDO_VERSION)
                    # A new complete request proves recovery after cancellation
                    # and that no previous prefix leaks into subsequent parsing.
                    w.apdu(bytes.fromhex('80100000') + bytes([len(LARGE_BLOB_GET)])
                           + LARGE_BLOB_GET, LARGE_BLOB_REPLY)
                    w.apdu(GET_RESPONSE, NO_RESPONSE)
                    cases.append(dict(
                        id=f'E67-{transport}-{payload_name}-split-{split}-{name}',
                        transport=transport, oracle_rows=['E21', 'E23', 'E67'],
                        preconditions='Fresh product; real Admin disables NDEF, real FIDO SELECT and two ISO input fragments. Expected chain retention follows C dispatch and transport envelope admission; no injected state or output-derived oracle.',
                        steps=w.steps,
                    ))
        # Interrupt before the schema is complete, then finish in the terminal
        # APDU. This also detects a retained ISO header with lost parser state.
        for split in range(1, len(LARGE_BLOB_GET)):
            for name, command, status, disposition in interruptions(aid):
                if disposition.startswith('extended-'):
                    if transport == 'ccid':
                        disposition, status = 'retain', WRONG_LENGTH
                    else:
                        disposition = disposition.removeprefix('extended-')
                if disposition == 'reject-select' and transport == 'nfc':
                    disposition = 'retain'
                elif disposition == 'malformed' and transport != 'nfc':
                    disposition = 'retain'
                if disposition != 'retain':
                    continue
                w = Wire(transport)
                w.apdu(ADMIN_SELECT, SUCCESS)
                w.apdu(ADMIN_VERIFY, SUCCESS)
                w.apdu(DISABLE_NDEF, SUCCESS)
                w.apdu(select(aid), FIDO_VERSION)
                w.apdu(bytes.fromhex('90100000') + bytes([split])
                       + LARGE_BLOB_GET[:split], SUCCESS)
                if command is not None:
                    w.apdu(command, status)
                suffix = LARGE_BLOB_GET[split:]
                w.apdu(bytes.fromhex('80100000') + bytes([len(suffix)])
                       + suffix, LARGE_BLOB_REPLY)
                w.apdu(GET_RESPONSE, NO_RESPONSE)
                w.apdu(VERSION, FIDO_VERSION)
                cases.append(dict(
                    id=f'E67-{transport}-resume-split-{split}-{name}',
                    transport=transport, oracle_rows=['E21', 'E23', 'E67'],
                    preconditions='Fresh product; a partial largeBlob CBOR schema precedes a C-preserved control command. Its remaining bytes arrive only in the terminal APDU and must produce the literal default blob byte80.',
                    steps=w.steps,
                ))
        # Relaxing active-chain admission must retain PIV's blanket extended
        # rejection. With no applet, global GET RESPONSE still returns6986.
        for prior in ['none', 'piv']:
            for cla in [0, 0x80]:
                for form, tail in [
                    ('short', b'\0'),
                    ('extended-le', b'\0\0\0'),
                    ('extended-body', bytes.fromhex('000001aa0000')),
                ]:
                    w = Wire(transport)
                    if prior == 'piv':
                        piv = bytes.fromhex('a000000308000010000100')
                        w.apdu(select(piv) + b'\x01', bytes.fromhex('616112'))
                        # Abandon the finite SELECT reply before the control;
                        # VERIFY with no grant reports the initial three retries.
                        w.apdu(bytes.fromhex('0020008000'), bytes.fromhex('63c3'))
                    extended = form != 'short'
                    status = WRONG_LENGTH if extended and (prior == 'piv' or transport == 'ccid') else NO_RESPONSE
                    w.apdu(bytes([cla, 0xc0, 0, 0]) + tail, status)
                    if prior == 'piv':
                        w.apdu(bytes.fromhex('0020008000'), bytes.fromhex('63c3'))
                    w.apdu(select(aid), FIDO_VERSION)
                    w.apdu(VERSION, FIDO_VERSION)
                    cases.append(dict(
                        id=f'E67-{transport}-{prior}-poll-cla-{cla:02x}-{form}',
                        transport=transport, oracle_rows=['E21', 'E23', 'E67'],
                        preconditions='Fresh product; no applet or real PIV SELECT/VERIFY. Extended polling must obey PIV rejection and short-only CCID while the unselected global response route returns6986.',
                        steps=w.steps,
                    ))
    return dict(schema=1, scope='Pending FIDO chain: GET RESPONSE, rejected/successful SELECT, malformed/extended transport admission, empty APDU and recovery.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
