#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real NFC WTX timers and reader IRQs during a real GetInfo command."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

from fido2 import cbor

from c312_auth_response import Nfc
from c312_ccid import ROOT, REVISION, build_c, digest


def build_execution_c(source, build, log):
    runner = build_c(source, build, log)
    source, build = source.resolve(), build.resolve()
    adapter = runner.parent
    unit = (adapter / 'runner.c').read_text()
    marker = '#include ' + json.dumps(str(ROOT / 'tests/support/c312_ccid.c'))
    assert unit.count(marker) == 1
    unit = unit.replace(marker, '#include ' + json.dumps(str(ROOT / 'tests/support/c312_nfc_execution.c')) + '\n' + marker)
    (adapter / 'runner.c').write_text(unit)
    commands = json.loads((build / 'compile_commands.json').read_text())

    def compile_object(original, replacement, output, extra=()):
        entry = next(x for x in commands if Path(x['file']) == original)
        args = entry.get('arguments') or shlex.split(entry['command'])
        args[args.index('-o') + 1] = str(output)
        args[args.index('-c') + 1] = str(replacement)
        subprocess.run(args + list(extra), cwd=entry['directory'], stdout=log, stderr=subprocess.STDOUT, check=True)

    compile_object(source / 'test/test_apdu.c', adapter / 'runner.c', adapter / 'runner.o')
    (adapter / 'runner.gcda').unlink(missing_ok=True)
    compile_object(source / 'src/fs.c', source / 'src/fs.c', adapter / 'execution-fs.o', ['-Dread_attr=portable_execution_read_attr_real'])
    args = shlex.split((build / 'test/CMakeFiles/test_apdu.dir/link.txt').read_text())
    args[args.index('-o') + 1] = str(runner)
    for i, arg in enumerate(args):
        if arg.endswith('/test_apdu.c.o'): args[i] = str(adapter / 'runner.o')
        elif arg.endswith('/virt-card/usb-dummy.c.o'): args[i] = str(adapter / 'dummy.o')
        elif arg.endswith('/src/fs.c.o'): args[i] = str(adapter / 'execution-fs.o')
    i = next(i for i, arg in enumerate(args) if arg.endswith('libcanokey-core.a'))
    args.insert(i, str(adapter / 'execution-fs.o'))
    subprocess.run(args, cwd=build / 'test', stdout=log, stderr=subprocess.STDOUT, check=True)
    return runner


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
                   count=count, reply='f2010000', disposition='equal')
    yield dict(name='echo-tick-wrap', mode='ARM', elapsed=150, count=1,
               reply='f2010000', wrap=True, disposition='equal')
    for name, reply in [('ack', 'a30000'), ('nak', 'b30000'), ('invalid', 'ff0000'),
                        ('deselect', 'c20000'), ('wtx', 'f2010000')]:
        yield dict(name=f'before-wtx-{name}', mode='BEFORE', elapsed=150, count=1,
                   reply=reply, disposition='equal')
    # These observations are deliberately not approvals of C's permissive
    # WTX handling or claims of parity. Keep their actual RF traces visible.
    for name, reply in [('wrong-echo', 'f2020000'), ('ack', 'a30000'),
                        ('nak', 'b30000'), ('deselect', 'c20000')]:
        yield dict(name=f'after-wtx-{name}', mode='ARM', elapsed=150, count=1,
                   reply=reply, disposition='unresolved')


def case(wire, rust, stimulus):
    assert wire.transmit(SELECT_FIDO) == (b'U2F_V2', 0x90, 0)
    if stimulus.get('wrap'):
        # Place the real command start before u32 tick wrap; timer advances
        # across it using the same production wrapping arithmetic.
        assert wire.raw('TICK 4294967200') == b''
    assert wire.control('{mode} {elapsed} {count} {reply}'.format(**stimulus)) == 'ARMED'
    response = wire.raw(GET_INFO_LE1)
    status = tuple(map(int, wire.control('STATUS').split()))
    fired = min(stimulus['count'], 2)  # This real GetInfo performs two FS reads.
    assert status == (stimulus['count'] - fired, fired, 0), status
    observed = list(wire.rf)
    expected = [WTX] * fired
    if stimulus['disposition'] == 'equal' or not rust:
        expected.append(FIRST_RESPONSE)
    assert observed == expected, (stimulus, observed, expected)
    # WIRE is only the fixture's last-send summary. RF records each TXEN and
    # is authoritative when cancellation leaves WIRE empty or showing WTX.
    if stimulus['disposition'] == 'equal':
        assert response.hex() == FIRST_RESPONSE, response.hex()
    assert wire.control('DISARM') == 'DISARMED'
    result = dict(rf=observed, wire_summary=response.hex(), status=status)
    if stimulus['disposition'] == 'equal':
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
        if rust and stimulus['name'] == 'after-wtx-deselect':
            assert settled == [WTX, 'c2'], settled
        else:
            assert settled == expected, settled
        result['settled_rf'] = settled
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-repository', type=Path)
    parser.add_argument('--c-build', type=Path)
    parser.add_argument('--rust-runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runners = []
    if args.c_repository:
        assert args.c_build
        with args.output.with_suffix('.build.log').open('w') as log:
            runners.append(('c', build_execution_c(args.c_repository, args.c_build, log)))
    runners.append(('rust', args.rust_runner.resolve()))
    files = [Path(__file__), ROOT / 'tests/support/c312_nfc_execution.c',
             ROOT / 'tests/card/src/storage.rs',
             ROOT / 'tests/card/src/bin/usb_sessions/portable_nfc.rs',
             ROOT / 'tests/card/src/bin/usb_sessions/nfc_execution.rs']
    report = dict(schema=1, scope='Actual GetInfo execution, scheduled WTX and reader IRQs; unresolved observations are not parity approvals.',
                  reference_revision=REVISION if args.c_repository else None,
                  fixtures=[dict(path=str(p.relative_to(ROOT)), sha256=digest(p)) for p in files],
                  results=[])
    try:
        for side, runner in runners:
            for stimulus in cases():
                wire = Execution(runner, side == 'rust')
                row = dict(side=side, case=stimulus['name'], stimulus=stimulus,
                           disposition=stimulus['disposition'], runner=str(runner),
                           runner_sha256=digest(runner), passed=False)
                report['results'].append(row)
                try:
                    row['observed'] = case(wire, side == 'rust', stimulus)
                    row['passed'] = True
                finally:
                    wire.close()
                    row.update(trace=wire.trace, rf=wire.rf, diagnostics=wire.diagnostics, stderr=wire.stderr)
        if args.c_repository:
            for stimulus in cases():
                rows = [r for r in report['results'] if r['case'] == stimulus['name']]
                assert len(rows) == 2
                equal = rows[0]['observed']['rf'] == rows[1]['observed']['rf']
                assert equal == (stimulus['disposition'] == 'equal'), rows
        report['summary'] = dict(
            equal_contract_cases=11, unresolved_cases=4,
            sides=[side for side, _ in runners],
            unresolved_are_parity_approvals=False,
        )
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary']))


if __name__ == '__main__':
    main()
