#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real NFC WTX timers and reader IRQs during a real GetInfo command."""
import argparse
import json
from pathlib import Path

from fido2 import cbor

from auth_response import Nfc
from wire_replay import digest

ROOT = Path(__file__).resolve().parents[2]


class Execution(Nfc):
    def __init__(self, *args):
        self.rf = []
        super().__init__(*args)

    def _read(self):
        for line in self.process.stdout:
            if line.startswith('RF '):
                self.rf.append(line.rstrip().split(' ', 1)[1])
            elif line.startswith(('WIRE ', 'EXEC ')):
                self.lines.put(tuple(line.rstrip('\n').split(' ', 1)))
            else:
                self.diagnostics.append(line.rstrip())
        self.lines.put(None)

    def control(self, value):
        self.process.stdin.write('EXEC ' + value + '\n')
        self.process.stdin.flush()
        answer = self.lines.get(timeout=30)
        assert answer is not None and answer[0] == 'EXEC', (answer, self.stderr, self.diagnostics)
        self.trace.append(dict(control=value, response=answer[1]))
        return answer[1]

    def raw(self, operation):
        self.process.stdin.write(operation + '\n')
        self.process.stdin.flush()
        answer = self.lines.get(timeout=30)
        assert answer is not None and answer[0] == 'WIRE', (answer, self.stderr, self.diagnostics)
        self.trace.append(dict(operation=operation, response=answer[1]))
        return bytes.fromhex(answer[1])


SELECT_FIDO = bytes.fromhex('00a4040008a0000006472f0001')
# BN1, FIDO CBOR GetInfo, Le1, followed by chip-checked CRC bytes.
GET_INFO_LE1 = 'NFC 03801000000104010000'
WTX = 'f201'
FIRST_RESPONSE = '030061ff'  # BN1, CTAP success, more ISO response bytes.


def cases():
    for elapsed, count in [(150, 1), (151, 1), (300, 1), (150, 2), (150, 4)]:
        yield dict(name=f'echo-{elapsed}ms-{count}-reads', mode='ARM', elapsed=elapsed,
                   count=count, reply='f2010000', completes=True)
    yield dict(name='echo-tick-wrap', mode='ARM', elapsed=150, count=1,
               reply='f2010000', wrap=True, completes=True)
    for name, reply in [('ack', 'a30000'), ('nak', 'b30000'), ('invalid', 'ff0000'),
                        ('deselect', 'c20000'), ('wtx', 'f2010000')]:
        yield dict(name=f'before-wtx-{name}', mode='BEFORE', elapsed=150, count=1,
                   reply=reply, completes=True)
    # Wrong or unexpected frames after a WTX request cancel the response.
    for name, reply in [('wrong-echo', 'f2020000'), ('ack', 'a30000'),
                        ('nak', 'b30000'), ('deselect', 'c20000')]:
        yield dict(name=f'after-wtx-{name}', mode='ARM', elapsed=150, count=1,
                   reply=reply, completes=False)


def case(wire, stimulus):
    if stimulus.get('wrap'):
        # Set the fixture clock before selection gives the link its first activity.
        assert wire.raw('DEFER TICK 4294967200') == b''
    assert wire.transmit(SELECT_FIDO) == (b'U2F_V2', 0x90, 0)
    assert wire.control('{mode} {elapsed} {count} {reply}'.format(**stimulus)) == 'ARMED'
    response = wire.raw(GET_INFO_LE1)
    status = tuple(map(int, wire.control('STATUS').split()))
    fired = min(stimulus['count'], 2)  # This real GetInfo performs two FS reads.
    assert status == (stimulus['count'] - fired, fired, 0), status
    observed = list(wire.rf)
    expected = [WTX] * fired
    if stimulus['completes']:
        expected.append(FIRST_RESPONSE)
    assert observed == expected, (stimulus, observed, expected)
    # WIRE is only the fixture's last-send summary. RF records each TXEN and
    # is authoritative when cancellation leaves WIRE empty or showing WTX.
    if stimulus['completes']:
        assert response.hex() == FIRST_RESPONSE, response.hex()
    assert wire.control('DISARM') == 'DISARMED'
    result = dict(rf=observed, wire_summary=response.hex(), status=status)
    if stimulus['completes']:
        wire.number = 0  # The manual BN1 request completed and returned BN1.
        payload = bytearray()
        for _ in range(8):
            data, sw1, sw2 = wire.transmit(bytes.fromhex('00c0000000'))
            payload.extend(data)
            if sw1 != 0x61:
                assert (sw1, sw2) == (0x90, 0), (sw1, sw2)
                break
        else:
            raise AssertionError('GetInfo response did not terminate')
        info = cbor.decode(bytes(payload))
        assert info[5] == 1296 and info[9] == ['nfc', 'usb'], info
        assert info[4]['rk'] is True and info[4]['clientPin'] is False, info[4]
        result['continuation_bytes'] = len(payload)
        # A fresh command also proves the same selected FIDO context survives.
        data, sw1, sw2 = wire.transmit(bytes.fromhex('80100000010401'))
        assert (data, sw1, sw2) == (b'\0', 0x61, 0xff)
        assert tuple(map(int, wire.control('STATUS').split())) == (0, fired, 0)
        result['continued_and_reused_selection'] = True
    else:
        for _ in range(3):
            wire.raw('POLL 0')
        settled = list(wire.rf)
        # Cancellation and its deferred protocol echo are distinct from an
        # APDU response; observe enough main-loop turns to distinguish them.
        if stimulus['name'] == 'after-wtx-deselect':
            assert settled == [WTX, 'c2'], settled
        else:
            assert settled == expected, settled
        result['settled_rf'] = settled
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runner = args.rust_runner.resolve()
    files = [Path(__file__),
             ROOT / 'tests/card/src/storage.rs',
             ROOT / 'tests/card/src/bin/usb_sessions/portable_nfc.rs',
             ROOT / 'tests/card/src/bin/usb_sessions/nfc_execution.rs']
    report = dict(schema=1, scope='GetInfo execution, scheduled WTX and reader IRQs',
                  fixtures=[dict(path=str(p.relative_to(ROOT)), sha256=digest(p)) for p in files],
                  results=[])
    try:
        for stimulus in cases():
            wire = Execution(runner)
            row = dict(case=stimulus['name'], stimulus=stimulus,
                       runner=str(runner),
                       runner_sha256=digest(runner), passed=False)
            report['results'].append(row)
            try:
                row['observed'] = case(wire, stimulus)
                row['passed'] = True
            finally:
                wire.close()
                row.update(trace=wire.trace, rf=wire.rf, diagnostics=wire.diagnostics, stderr=wire.stderr)
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"NFC execution: {len(report['results'])} cases passed")


if __name__ == '__main__':
    main()
