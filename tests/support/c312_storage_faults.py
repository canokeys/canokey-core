#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inject one negative/short response-file read through actual C/Rust transports.

Production C sources remain pinned and unchanged. Only fs.c's read_file symbol
is renamed in a separate host build so the adapter can forward or inject a read.
Rust retains exact read_at for CTAP/native HID, and exposes actual prefix counts
through read_some_at for ISO U2F registration. Unreported suffix bytes are poisoned.
Rust USB presence uses raw samples and the production Polling state machine;
pinned C retains its existing TEST-mode touch emulator. No applet result is stubbed.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

from c312_auth_response import Checks, Nfc, Usb, ROOT, SOURCE_CHUNK, provision
from c312_ccid import REVISION, build_c, digest
from c312_large_blob import hid_reports

RECORD_BLOB = 180
RECORD_CERTIFICATE = 183
# A host-polled registration must observe a complete100 ms raw-sensor cycle.
U2F_POLL_INTERVAL_MS = 10
U2F_POLL_RETRIES = 20
PRESENCE_REQUIRED = 0x6985
# Unknown CTAP data forces the actual NFC body through PKE staging (>279 B).
EXTENDED_PADDING = b'\x5a' * 300
EXTENDED_PADDING_LABEL = 0x7f
NFC_EXTENDED_ENCODINGS = ('case3e', 'case4e-257', 'case4e-65536')
# ISO-DEP PCB fields; NFC packets here exclude the frontend-generated CRC.
NFC_BLOCK_NUMBER = 0x01
NFC_CHAIN = 0x10
NFC_INFORMATION = 0x02
NFC_ACK = 0xa2
NFC_NAK = 0xb2


class HidFailure(Exception):
    pass


class Faults:
    def _read(self):
        for line in self.process.stdout:
            if line.startswith(("WIRE ", "HID ", "BULK ", "FAULT ")):
                self.lines.put(tuple(line.rstrip("\n").split(" ", 1)))
            else:
                self.diagnostics.append(line.rstrip())
        self.lines.put(None)

    def control(self, command):
        self.process.stdin.write("FAULT " + command + "\n")
        self.process.stdin.flush()
        answer = self.lines.get(timeout=30)
        assert answer is not None, (self.process.poll(), self.diagnostics, self.stderr)
        key, value = answer
        assert key == "FAULT", answer
        self.trace.append(dict(control=command, response=value))
        return value


class FaultNfc(Faults, Nfc):
    replay_response = False
    retransmissions = 0

    def transmit(self, frame):
        self.replay_first = True
        return super().transmit(frame)

    def packet(self, frame):
        reply = super().packet(frame)
        if (self.replay_response
                and reply[0] & ~NFC_BLOCK_NUMBER in (NFC_INFORMATION, NFC_INFORMATION | NFC_CHAIN)
                and (self.replay_first or not reply[0] & NFC_CHAIN)):
            self.replay_first = False
            status = self.control('STATUS')
            number = reply[0] & NFC_BLOCK_NUMBER
            # Rule11 repeats the cached I-block without another source read.
            assert super().packet(bytes([NFC_NAK | number])) == reply
            assert self.control('STATUS') == status
            # Rule12 answers an opposite-BN NAK without advancing the source.
            ack = bytes([NFC_ACK | number])
            assert super().packet(bytes([NFC_NAK | (number ^ NFC_BLOCK_NUMBER)])) == ack
            assert self.control('STATUS') == status
            # The last transmitted block is now R(ACK), not the older I-block.
            assert super().packet(bytes([NFC_NAK | number])) == ack
            assert self.control('STATUS') == status
            self.retransmissions += 2
        return reply


class FaultUsb(Faults, Usb):
    def event(self, command, data=b""):
        result = super().event(command, data)
        reports = result["HID"]
        for offset in range(0, len(reports), 64):
            packet = reports[offset:offset + 64]
            if packet[4] == 0xbf:
                assert packet[:8] == bytes.fromhex("12345678bf00017f"), packet.hex()
                raise HidFailure(packet.hex())
        return result

    def cbor(self, body):
        reports = bytearray()
        for frame in hid_reports(0x90, body):
            event = self.event('HID', frame)
            assert not event['WIRE'] and not event['BULK']
            reports.extend(event['HID'])
        payload, total, sequence = bytearray(), None, 0
        for offset in range(0, len(reports), 64):
            packet = reports[offset:offset + 64]
            assert packet[:4] == bytes.fromhex('12345678')
            if packet[4] == 0xbb:
                assert packet[5:8] in (b'\0\x01\x01', b'\0\x01\x02')
                continue
            if total is None:
                assert packet[4] == 0x90
                total = int.from_bytes(packet[5:7], 'big')
                start = 7
            else:
                assert packet[4] == sequence
                sequence += 1
                start = 5
            payload.extend(packet[start:start + min(64 - start, total - len(payload))])
        assert total is not None and len(payload) == total
        return bytes(payload)


def build_fault_c(source, build, log):
    runner = build_c(source, build, log)
    source, build = source.resolve(), build.resolve()
    adapter = runner.parent
    unit = (adapter / "runner.c").read_text()
    marker = '#include ' + json.dumps(str(ROOT / 'tests/support/c312_ccid.c'))
    assert unit.count(marker) == 1
    unit = unit.replace(marker, '#include ' + json.dumps(str(ROOT / 'tests/support/c312_storage_faults.c')) + '\n' + marker)
    (adapter / 'runner.c').write_text(unit)
    commands = json.loads((build / 'compile_commands.json').read_text())

    def compile_object(original, replacement, output, extra=()):
        entry = next(item for item in commands if Path(item['file']) == original)
        args = entry.get('arguments') or shlex.split(entry['command'])
        args[args.index('-o') + 1] = str(output)
        args[args.index('-c') + 1] = str(replacement)
        subprocess.run(args + list(extra), cwd=entry['directory'], stdout=log, stderr=subprocess.STDOUT, check=True)

    compile_object(source / 'test/test_apdu.c', adapter / 'runner.c', adapter / 'runner.o')
    (adapter / 'runner.gcda').unlink(missing_ok=True)
    compile_object(source / 'src/fs.c', source / 'src/fs.c', adapter / 'fault-fs.o', ['-Dread_file=portable_read_file_real'])
    args = shlex.split((build / 'test/CMakeFiles/test_apdu.dir/link.txt').read_text())
    args[args.index('-o') + 1] = str(runner)
    for index, arg in enumerate(args):
        if arg.endswith('/test_apdu.c.o'):
            args[index] = str(adapter / 'runner.o')
        elif arg.endswith('/virt-card/usb-dummy.c.o'):
            args[index] = str(adapter / 'dummy.o')
        elif arg.endswith('/src/fs.c.o'):
            args[index] = str(adapter / 'fault-fs.o')
    # fs.c is an archive member; satisfy all its symbols before the archive
    # so the unchanged original object is not extracted as a second definition.
    index = next(i for i, arg in enumerate(args) if arg.endswith('libcanokey-core.a'))
    args.insert(index, str(adapter / 'fault-fs.o'))
    subprocess.run(args, cwd=build / 'test', stdout=log, stderr=subprocess.STDOUT, check=True)
    return runner


def request(wire, ins, data, cla=0, encoding='short'):
    """Drain one response, retaining published prefixes and exact failure kind."""
    windows, payload, polling = [], bytearray(), []
    pending_fault = wire.control('STATUS') if ins == 1 and wire.kind != 'nfc' else None
    try:
        if wire.kind == 'cbor':
            assert ins == 0x10 and cla == 0x80
            payload = wire.cbor(data)
            assert payload[0] == 0, payload.hex()
            return dict(outcome='success', windows=[], payload=payload.hex())
        if encoding != 'short':
            assert wire.kind == 'nfc' and encoding in NFC_EXTENDED_ENCODINGS
            raw = bytes([cla, ins, 0, 0, 0]) + len(data).to_bytes(2, 'big') + data
            if encoding != 'case3e':
                raw += (257 if encoding == 'case4e-257' else 0).to_bytes(2, 'big')
        elif wire.kind == 'msg':
            raw = bytes([cla, ins, 0, 0, 0]) + len(data).to_bytes(2, 'big') + data + b'\0\0'
        else:
            parts = [data[i:i + 193] for i in range(0, len(data), 193)] or [b'']
            for part in parts[:-1]:
                assert wire.transmit(bytes([cla | 0x10, ins, 0, 0, len(part)]) + part) == (b'', 0x90, 0)
            raw = bytes([cla, ins, 0, 0]) + (bytes([len(parts[-1])]) + parts[-1] if parts[-1] else b'') + b'\0'
        while True:
            part, hi, lo = wire.transmit(raw)
            sw = hi * 256 + lo
            if ins == 1 and wire.kind != 'nfc' and sw == PRESENCE_REQUIRED:
                # CTAP1 is host-polled. Advance the raw sensor waveform through
                # the ordinary main-loop sampler; never supply a poll result.
                assert not part and not windows and not payload
                assert len(polling) < U2F_POLL_RETRIES, f'No completed CTAP1 gesture within {U2F_POLL_INTERVAL_MS * U2F_POLL_RETRIES} ms'
                status = wire.control('STATUS')
                assert status == pending_fault, (pending_fault, status)
                polling.append(dict(sw=sw, fault_status=status))
                wire.tick(U2F_POLL_INTERVAL_MS)
                continue
            if sw != 0x9000 and hi != 0x61:
                if encoding != 'short' and not windows:
                    # Previously published internal chunks cannot be retracted.
                    # The failed exact-read chunk itself publishes no bytes.
                    assert len(part) % SOURCE_CHUNK == 0, (encoding, sw, len(part))
                else:
                    assert not part, (hex(sw), part.hex())
            windows.append(dict(length=len(part), sw=sw, data=part.hex()))
            payload.extend(part)
            if hi != 0x61:
                return dict(outcome='success' if sw == 0x9000 else 'iso-error', windows=windows, payload=payload.hex(), sw=sw, polling=polling)
            raw = bytes.fromhex('00c0000000')
    except HidFailure as error:
        return dict(outcome='hid-error', windows=windows, payload=payload.hex(), error=str(error), polling=polling)


def suite(wire, rust, encoding='short'):
    import hashlib
    checks = Checks(wire)
    verify = provision(checks.card)
    checks.select()
    challenge = hashlib.sha256(b'C312 response storage faults').digest()
    rp = 'fault.example'
    app = hashlib.sha256(rp.encode()).digest()
    blob = bytes(range(256)) * 4
    blob += hashlib.sha256(blob).digest()[:16]
    for offset in range(0, len(blob), 400):
        params = {2: blob[offset:offset + 400], 3: offset}
        if offset == 0:
            params[4] = len(blob)
        checks.ctap(f'upload-{offset}', 12, params)

    # Baseline MC proves that the real certificate/key and generated response
    # are valid; recoveries after every injected failure reverify them.
    params = {1: challenge, 2: {'id': rp}, 3: {'id': b'fault-user'},
              4: [{'type': 'public-key', 'alg': -7}]}
    baseline = checks.ctap('baseline-make', 1, params, source=True)
    verify(baseline, challenge)
    attestation = x509.load_der_x509_certificate(baseline[3]['x5c'][0]).public_key()
    sources = [('make-classical', RECORD_CERTIFICATE, 0x10, b'\x01' + cbor.encode(params), 0x80),
               ('large-blob', RECORD_BLOB, 0x10, b'\x0c' + cbor.encode({1: len(blob), 3: 0}), 0x80)]
    # Native CBOR has no CTAP1 envelope; all ISO and native MSG paths use the
    # real U2F command and ordinary presence policy.
    if wire.kind != 'cbor':
        sources.append(('u2f-register', RECORD_CERTIFICATE, 1, challenge + app, 0))
    for algorithm in [-49] + ([-48] if rust else []):
        sources.append((f'make-{algorithm}', RECORD_CERTIFICATE, 0x10,
                        b'\x01' + cbor.encode(params | {4: [{'type': 'public-key', 'alg': algorithm}]}), 0x80))
    if encoding != 'short':
        assert wire.kind == 'nfc'
        # Exercise real staged requests, not just extended envelopes with an
        # inline-sized body. CTAP ignores this unknown map entry on both sides.
        sources = [(label, record, ins,
                    data[:1] + cbor.encode(cbor.decode(data[1:]) | {EXTENDED_PADDING_LABEL: EXTENDED_PADDING})
                    if ins == 0x10 else data, cla)
                   for label, record, ins, data, cla in sources]
        wire.replay_response = True

    def verify_success(label, result):
        assert result['outcome'] == 'success', (label, result)
        if encoding != 'short':
            first = result['windows'][0]
            if encoding == 'case4e-257':
                assert first['length'] == 257 and first['sw'] >> 8 == 0x61, first
            else:
                assert len(result['windows']) == 1 and first['sw'] == 0x9000
        payload = bytes.fromhex(result['payload'])
        if label.startswith('make'):
            assert payload[0] == 0
            verify(cbor.decode(payload[1:]), challenge)
        elif label == 'large-blob':
            assert payload == b'\0' + cbor.encode({1: blob})
        else:
            assert payload[:2] == b'\x05\x04'
            handle = payload[67:67 + payload[66]]
            tail = payload[67 + len(handle):]
            cert = baseline[3]['x5c'][0]
            assert tail[:len(cert)] == cert
            attestation.verify(tail[len(cert):], b'\0' + app + challenge + handle + payload[1:66], ec.ECDSA(hashes.SHA256()))

    cases = []
    for label, record, ins, data, cla in sources:
        for skip in (0, 1):
            for returned in (-1, 0, 1):
                assert wire.control(f'ARM {record} {skip} {returned}') == 'ARMED'
                start = len(wire.trace)
                result = request(wire, ins, data, cla, encoding)
                active, hits, offset, requested, observed = map(int, wire.control('STATUS').split())
                assert (active, hits, observed) == (0, 1, returned), (label, skip, returned, result)
                assert requested > max(returned, 0)
                # Generic CTAP file segments and native HID require full reads.
                # C's ISO U2F source explicitly permits positive progress and
                # retries after a short read. Rust exposes that same prefix count.
                partial_success = label == 'u2f-register' and wire.kind != 'msg' and (returned == 1 or skip == 0 and returned == 0)
                expected = 'success' if partial_success else 'hid-error' if wire.kind in ('msg', 'cbor') else 'iso-error'
                assert result['outcome'] == expected, (label, skip, returned, expected, result)
                if partial_success:
                    verify_success(label, result)
                elif wire.kind not in ('msg', 'cbor'):
                    assert result['sw'] == 0x6900
                if label == 'large-blob':
                    # All published bytes precede the failed exact-read chunk;
                    # the poisoned remainder must never appear on the wire.
                    expected_blob = b'\0' + cbor.encode({1: blob})
                    payload = bytes.fromhex(result['payload'])
                    assert payload == expected_blob[:len(payload)]
                # Probe before recovery so command replacement cannot mask a
                # source that incorrectly survived the failed read.
                probe = wire.transmit(bytes.fromhex('00c0000000'))
                expected_probe = (b'', 0x6d, 0) if wire.kind == 'msg' else (b'', 0x69, 0x86)
                assert probe == expected_probe, probe
                recovery = request(wire, ins, data, cla, encoding)
                verify_success(label, recovery)
                cases.append(dict(case=f'{label}-skip{skip}-return{returned}', passed=True,
                                  fault=dict(record=record, skip=skip, returned=returned, offset=offset, requested=requested),
                                  result=result, source_probe=dict(data=probe[0].hex(), sw=probe[1] * 256 + probe[2]),
                                  recovery=recovery, trace=wire.trace[start:]))
    if rust and wire.kind in ('ccid', 'webusb', 'msg'):
        registrations = [case for case in cases if case['case'].startswith('u2f-register')]
        # A completed gesture is consumed once. At least one following request
        # must wait for a new sampled release, with the file-fault state intact.
        assert any(case['result']['polling'] for case in registrations)
        assert any(case['recovery']['polling'] for case in registrations)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-runner', type=Path, required=True)
    parser.add_argument('--c-repository', type=Path)
    parser.add_argument('--c-build', type=Path)
    parser.add_argument('--transport', choices=('ccid', 'webusb', 'msg', 'cbor', 'nfc'), action='append')
    parser.add_argument('--nfc-extended', action='store_true',
                        help='exercise staged NFC Case3E and Case4E (Le257/65536) response-file faults')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.nfc_extended:
        assert args.transport == ['nfc'], '--nfc-extended requires --transport nfc'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runners = []
    if args.c_repository:
        assert args.c_build
        with args.output.with_suffix('.build.log').open('w') as log:
            runners.append(('c', build_fault_c(args.c_repository, args.c_build, log)))
    runners.append(('rust', args.rust_runner.resolve()))
    files = [Path(__file__), ROOT / 'tests/support/c312_storage_faults.c', ROOT / 'tests/support/c312_ccid.py',
             ROOT / 'tests/support/c312_auth_response.py', ROOT / 'tests/card/src/transport.rs',
             ROOT / 'tests/card/src/storage.rs', ROOT / 'tests/card/src/bin/usb_sessions/portable_nfc.rs',
             ROOT / 'tests/card/src/bin/usb_sessions/portable_webusb.rs']
    report = dict(schema=1, scope='Response-file faults and observable recovery; independent assertions, not byte equality or physical storage acceptance',
                  reference_revision=REVISION if args.c_repository else None,
                  fixtures=[dict(path=str(p.relative_to(ROOT)), sha256=digest(p)) for p in files], results=[])
    try:
        for side, runner in runners:
            for kind in args.transport or ['ccid', 'webusb', 'msg', 'cbor', 'nfc']:
                for encoding in NFC_EXTENDED_ENCODINGS if args.nfc_extended else ('short',):
                    wire = FaultNfc(runner, side == 'rust') if kind == 'nfc' else FaultUsb(runner, side == 'rust', kind)
                    entry = dict(side=side, transport=kind, encoding=encoding,
                                 runner=str(runner), runner_sha256=digest(runner), passed=False)
                    report['results'].append(entry)
                    try:
                        entry['cases'] = suite(wire, side == 'rust', encoding)
                        entry['passed'] = True
                    except Exception as error:
                        entry['error'] = repr(error)
                        raise
                    finally:
                        try:
                            wire.close()
                        finally:
                            entry.update(trace=wire.trace, apdus=wire.apdus, diagnostics=wire.diagnostics, stderr=wire.stderr)
                            if kind == 'nfc':
                                entry['retransmissions'] = wire.retransmissions
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({r['side'] + '-' + r['transport'] + '-' + r['encoding']: len(r['cases']) for r in report['results']}))


if __name__ == '__main__':
    main()
