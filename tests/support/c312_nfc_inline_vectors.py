#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate malformed inline NFC contracts without consulting runner output."""
import argparse
import json
from pathlib import Path

from c312_nfc_rejection_vectors import PRIORS, begin, command, end, fragmented
from c312_select_vectors import WRONG_LENGTH


def envelopes():
    # ISO Case3E/4E permits zero or two Le bytes. A truncated one-byte
    # body leaves Case2E, so that well-formed envelope is deliberately excluded.
    for header in ['80100000', '00d60000', '00da7f21', '00a404ff', '80c0ffff']:
        for length in [1, 2, 254, 255, 256, 279]:
            for form in ['tail1', 'tail3', 'truncated']:
                if length == 1 and form == 'truncated':
                    continue
                yield f'{header}-lc-{length}-{form}', command(bytes.fromhex(header), length, form)
    # Short headers, missing extended length, zero extended Lc with body,
    # truncated short body and excessive short Le cannot reach applet routing.
    for encoded in ['', '00', '00a4', '00a404', '00d600000001',
                    '00d6000000000000', '00d600000000000000',
                    '00d600000261', '00d6000001610000']:
        yield f'length-{len(encoded) // 2}-{encoded or "empty"}', bytes.fromhex(encoded)


def generate():
    cases = []
    for prior in PRIORS:
        for label, request in envelopes():
            w = begin(prior)
            if request:
                w.apdu(request, WRONG_LENGTH)
            else:
                # Empty ISO-DEP INF is still a complete malformed APDU.
                pcb = 0x02 | w.number
                w.steps.append(dict(packet=(bytes([pcb]) + bytes(2)).hex(),
                                    expected=(bytes([pcb]) + WRONG_LENGTH).hex()))
                w.number ^= 1
            end(w, prior, True, False)
            cases.append(record(prior, label, w))
        for first in range(1, 8):
            for repeat in [False, True]:
                w = begin(prior)
                # The invalid one-byte Le is detected after every header split;
                # retries must never invoke abort or consume a cursor twice.
                fragmented(w, command(bytes.fromhex('80100000'), 255, 'tail1'),
                           WRONG_LENGTH, first, repeat)
                end(w, prior, True, False)
                cases.append(record(prior, f'first-{first}-repeat-{int(repeat)}', w))
    return dict(schema=1, scope='Malformed inline ISO NFC envelopes reject before applet dispatch; FIDO input/output closes, unrelated applet cursors and grants survive.', cases=cases)


def record(prior, label, wire):
    return dict(id=f'E70-{prior}-{label}', transport='nfc', oracle_rows=['E70'],
                preconditions='Real prior FIDO input/GetInfo output or NDEF/OpenPGP write cursor and PW3. ISO envelope lengths are invalid independently of CLA/INS/P1/P2. Literal continuation/readback, grant and fresh requests assert cleanup and recovery; no output-derived oracle.',
                steps=wire.steps)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
