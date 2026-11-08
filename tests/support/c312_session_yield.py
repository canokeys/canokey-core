#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise retained PIV state across actual USB facades with independent crypto.

The C runner uses pinned, unchanged production sources. Random challenges and
SM2 ephemerals are verified independently; this is not byte-equivalence testing.
"""
import argparse
import json
from pathlib import Path

from fido2 import cbor

from c312_auth_response import ROOT, Usb
from c312_ccid import REVISION, build_c, digest
from c312_large_blob import hid_reports
from card_test import fields, tlv
from piv_normal import Piv, KEY, aes
import piv_sm2 as sm2


class Session(Usb):
    def hid(self, command, body, staged_refusal=False):
        frames = hid_reports(command, body)
        reports = bytearray()
        # A rejected initial staged header must not be followed by its payload.
        for frame in frames[:1] if staged_refusal else frames:
            event = self.event('HID', frame)
            assert not event['WIRE'] and not event['BULK'], event
            reports.extend(event['HID'])
        payload, tag, total, sequence = bytearray(), None, None, 0
        offset = 0
        while offset < len(reports) or (total is not None and len(payload) < total):
            if offset == len(reports):
                event = self.event("POLL")
                assert event["HID"] and not event["WIRE"] and not event["BULK"], event
                reports.extend(event["HID"])
            packet = reports[offset:offset + 64]
            offset += 64
            assert len(packet) == 64 and packet[:4] == bytes.fromhex('12345678')
            if packet[4] == 0xbb:
                assert packet[5:8] in (b'\0\x01\x01', b'\0\x01\x02')
                continue
            if tag is None:
                tag = packet[4]
                total = int.from_bytes(packet[5:7], 'big')
                start = 7
            else:
                assert packet[4] == sequence
                sequence += 1
                start = 5
            payload.extend(packet[start:start + min(64 - start, total - len(payload))])
        assert tag is not None and len(payload) == total, reports.hex()
        return tag, bytes(payload)


def suite(wire, entry):
    piv = Piv(wire)
    cases = entry["cases"] = []
    entry["applet_checks"] = piv.report

    def check(label, actual, expected):
        entry = dict(case=label, passed=actual == expected,
                     actual=repr(actual), expected=repr(expected))
        cases.append(entry)
        assert entry['passed'], entry

    def control(label, command, payload):
        check(label, wire.hid(command, payload),
              (command, payload if command == 0x81 else b''))

    def get_info(label):
        tag, payload = wire.hid(0x90, b'\x04')
        check(label + '-status', (tag, payload[:1]), (0x90, b'\0'))
        info = cbor.decode(payload[1:])
        check(label + '-capacity', info[5], 1296)

    def version(label):
        check(label, wire.hid(0x83, bytes.fromhex('00030000000000')),
              (0x83, b'U2F_V2\x90\0'))

    def busy(label, command, body, staged=False):
        check(label, wire.hid(command, body, staged), (0xbf, b'\x06'))

    piv.select()
    piv.verify()
    for label, operation in [('idle-getinfo', get_info), ('idle-version', version)]:
        operation(label)
        piv.cmd(label + '-pin-survives', 0x20, 0, 0x80, le=None)
    # Both authentication modes keep their challenge outside shared scratch.
    for mutual in (False, True):
        label = 'mutual' if mutual else 'external'
        tag = 0x80 if mutual else 0x81
        reply = piv.cmd(label + '-challenge', 0x87, 0x0a, 0x9b, tlv(0x7c, tlv(tag, b'')))
        challenge = fields(fields(reply)[0x7c])[tag]
        check(label + '-challenge-size', len(challenge), 16)
        control(label + '-ping', 0x81, b'preserve challenge')
        get_info(label + '-getinfo')
        version(label + '-version')
        if mutual:
            host = bytes(range(16))
            response = piv.cmd(label + '-proof', 0x87, 0x0a, 0x9b,
                               tlv(0x7c, tlv(0x80, aes(KEY, challenge, True)) + tlv(0x81, host)))
            check(label + '-verified', response, tlv(0x7c, tlv(0x82, aes(KEY, host))))
        else:
            response = piv.cmd(label + '-proof', 0x87, 0x0a, 0x9b,
                               tlv(0x7c, tlv(0x82, aes(KEY, challenge))), le=None)
            check(label + '-verified', response, b'')
    piv.cmd('sm2-import', 0xfe, 0x54, 0x9a, tlv(6, sm2.V_DA), le=None)
    piv.verify()
    start = tlv(0x7c, tlv(0x82, b''))
    peer = tlv(0x86, b'\x04' + sm2.V_PB) + tlv(0x87, b'\x04' + sm2.V_EB)
    finish = tlv(0x7c, tlv(0x82, b'') + tlv(0x85, peer))
    for own in (None, b'card retained identity'):
        label = 'sm2-custom' if own else 'sm2-default'
        initial = piv.cmd(label + '-start', 0x87, 0x54, 0x9a,
                          tlv(0x7c, (tlv(0x80, own) if own else b'') + tlv(0x82, b'')))
        ephemeral = fields(fields(initial)[0x7c])[0x82]
        check(label + '-ephemeral-size', (len(ephemeral), ephemeral[:1]), (65, b'\x04'))
        for length in (0, 57, 58, 192):
            control(label + '-ping-' + str(length), 0x81, bytes(range(length)))
        for length in (0, 58, 192):
            control(label + '-wink-' + str(length), 0x88, bytes(range(length)))
        busy(label + '-getinfo-busy', 0x90, b'\x04')
        busy(label + '-version-busy', 0x83, bytes.fromhex('00030000000000'))
        check(label + '-empty-cbor', wire.hid(0x90, b''), (0xbf, b'\x03'))
        check(label + '-short-msg', wire.hid(0x83, bytes(6)), (0xbf, b'\x03'))
        busy(label + '-malformed-msg-busy', 0x83, bytes.fromhex('00030000000001'))
        busy(label + '-staged-ping-busy', 0x81, bytes(193), True)
        busy(label + '-staged-cbor-busy', 0x90, b'\x04' + bytes(192), True)
        reply = piv.cmd(label + '-finish', 0x87, 0x54, 0x9a, finish)
        expected = sm2.key_exchange_full(
            1, sm2.ID_DEFAULT, own or sm2.ID_DEFAULT, sm2.V_DB, sm2.V_PB,
            sm2.V_RB, sm2.V_EB, sm2.V_PA, ephemeral[1:], 16)[0]
        check(label + '-independent-key', fields(fields(reply)[0x7c]), {0x82: expected})
        get_info(label + '-released')
        piv.cmd(label + '-pin-survives', 0x20, 0, 0x80, le=None)
    # Same-owner interruption must release the guard as well as erase scratch.
    for interruption in ('verify', 'select', 'failure'):
        piv.cmd(interruption + '-start', 0x87, 0x54, 0x9a, start)
        busy(interruption + '-busy', 0x90, b'\x04')
        if interruption == 'verify':
            piv.verify()
        elif interruption == 'select':
            piv.select()
        else:
            piv.cmd('invalid-sm2-peer', 0x87, 0x54, 0x9a,
                    tlv(0x7c, tlv(0x82, b'') + tlv(0x85, b'\x04' + sm2.V_PB)), status=0x6a80)
        get_info(interruption + '-released')
        # Recovery must execute a fresh responder, independently checked.
        reply = fields(fields(piv.cmd(interruption + '-recover', 0x87, 0x54, 0x9a, finish))[0x7c])
        expected = sm2.key_exchange_full(0, sm2.ID_DEFAULT, sm2.ID_DEFAULT,
            sm2.V_DB, sm2.V_PB, sm2.V_RB, sm2.V_EB, sm2.V_PA, reply[0x82][1:], 16)[0]
        check(interruption + '-independent-key', reply[0x85], expected)
    # Input chains and response leases protect the same shared workspace for
    # PIV and OpenPGP; verify actual stored bytes after a refused native borrow.
    piv.auth()
    value = bytes(range(256)) + b'certificate suffix'
    body = tlv(0x5c, bytes.fromhex('5fc105')) + tlv(0x53, value)
    piv.raw('piv-put-start', 0xdb, 0x3f, 0xff, body[:100], cla=0x10)
    busy('piv-put-chain-busy', 0x90, b'\x04')
    piv.raw('piv-put-finish', 0xdb, 0x3f, 0xff, body[100:])
    first = piv.raw('piv-object-first', 0xcb, 0x3f, 0xff,
                    tlv(0x5c, bytes.fromhex('5fc105')), le=1, status=0x61ff)
    control('piv-object-response-ping', 0x81, b'preserve object cursor')
    busy('piv-object-response-busy', 0x90, b'\x04')
    rest = piv.cmd('piv-object-rest', 0xc0)
    check('piv-object-bytes', first + rest, tlv(0x53, value))
    get_info('piv-object-released')

    pgp = Piv(wire)
    pgp.cmd('openpgp-select', 0xa4, 4, data=bytes.fromhex('d27600012401'))
    pgp.cmd('openpgp-admin', 0x20, 0, 0x83, b'12345678', le=None)
    pgp.raw('openpgp-cert-start', 0xda, 0x7f, 0x21, value[:100], cla=0x10)
    busy('openpgp-cert-chain-busy', 0x90, b'\x04')
    pgp.raw('openpgp-cert-finish', 0xda, 0x7f, 0x21, value[100:])
    first = pgp.raw('openpgp-cert-first', 0xca, 0x7f, 0x21, le=1, status=0x61ff)
    control('openpgp-cert-response-ping', 0x81, b'preserve certificate cursor')
    busy('openpgp-cert-response-busy', 0x90, b'\x04')
    rest = pgp.cmd('openpgp-cert-rest', 0xc0)
    check('openpgp-cert-bytes', first + rest, value)
    get_info('openpgp-cert-released')
    pgp.cmd('openpgp-admin-survives', 0x20, 0, 0x83, le=None)
    piv.report['passed'] = True
    pgp.report['passed'] = True
    entry['openpgp_checks'] = pgp.report
    return cases, piv.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-runner', type=Path, required=True)
    parser.add_argument('--c-repository', type=Path)
    parser.add_argument('--c-build', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runners = []
    if args.c_repository:
        assert args.c_build
        with args.output.with_suffix('.build.log').open('w') as log:
            runners.append(('c', build_c(args.c_repository, args.c_build, log)))
    runners.append(('rust', args.rust_runner.resolve()))
    report = dict(schema=1, scope='Retained applet scratch and USB borrowing; independent assertions, not byte equality',
                  reference_revision=REVISION if args.c_repository else None,
                  fixtures=[dict(path=str(p.relative_to(ROOT)), sha256=digest(p)) for p in (
                      Path(__file__), ROOT / 'tests/support/c312_auth_response.py',
                      ROOT / 'tests/support/c312_ccid.c', ROOT / 'tests/integration/piv_sm2.py')], results=[])
    try:
        for side, runner in runners:
            for kind in ('ccid', 'webusb'):
                wire = Session(runner, side == 'rust', kind)
                entry = dict(side=side, transport=kind, runner=str(runner), runner_sha256=digest(runner), passed=False)
                report['results'].append(entry)
                try:
                    suite(wire, entry)
                    entry['passed'] = True
                except Exception as error:
                    entry['error'] = repr(error)
                    raise
                finally:
                    try:
                        wire.close()
                    finally:
                        entry.update(trace=wire.trace, apdus=wire.apdus,
                                     diagnostics=wire.diagnostics, stderr=wire.stderr)
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({r['side'] + '-' + r['transport']: len(r['cases']) for r in report['results']}))


if __name__ == '__main__':
    main()
