#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run response-file contracts through a real platform LittleFS composition.

The host provides raw Core APDUs, not simulated USB packets. File-read faults
must be injected below the production storage service's count validation.
"""
import argparse
import json
from pathlib import Path
import subprocess

from c312_ccid import digest
from c312_storage_faults import suite


class Native:
    kind = 'native-apdu'

    def __init__(self, host):
        self.process = subprocess.Popen([str(host)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1)
        self.trace, self.apdus = [], []

    def command(self, line):
        self.process.stdin.write(line + '\n')
        self.process.stdin.flush()
        answer = self.process.stdout.readline().rstrip('\n')
        assert answer, (line, self.process.poll())
        self.trace.append(dict(command=line, response=answer))
        return answer

    def control(self, line):
        answer = self.command('FAULT ' + line)
        assert answer.startswith('FAULT '), answer
        return answer[6:]

    def transmit(self, raw):
        reply = bytes.fromhex(self.command(raw.hex()))
        assert len(reply) >= 2
        self.apdus.append(dict(request=raw.hex(), response=reply.hex()))
        return reply[:-2], reply[-2], reply[-1]

    def tick(self, milliseconds):
        # The native fixture advances one millisecond and samples raw presence
        # per POLL iteration, using its real Device adapter and Polling latch.
        assert self.command(f'POLL {milliseconds}') == '9000'

    def close(self):
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        assert code == 0, (code, self.process.stderr.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    wire = Native(args.host.resolve())
    report = dict(schema=1, scope='Real native LittleFS response-file contracts over Core APDUs; not USB/RF or physical flash acceptance',
                  runner_sha256=digest(args.host), passed=False)
    try:
        report['cases'] = suite(wire, rust=True)
        registrations = [c for c in report['cases'] if c['case'].startswith('u2f-register')]
        assert any(c['result']['polling'] for c in registrations)
        assert any(c['recovery']['polling'] for c in registrations)
        report['passed'] = True
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        try:
            wire.close()
        finally:
            report.update(trace=wire.trace, apdus=wire.apdus)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Native LittleFS response checks: {len(report['cases'])} passed")


if __name__ == '__main__':
    main()
