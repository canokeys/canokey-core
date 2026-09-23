#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normal OATH APDU flows, shared by host card and dedicated DevKit.
Writes throwaway credentials/PASS slots and clears them at successful completion.
Failures can leave test state; rerunning starts with authenticated OATH/PASS reset.
Use a dedicated device with default ADMIN PIN 123456.
No boundary, fault injection or fuzz tests. --host also tests physical-output
service and request-bound presence using the host input fixture.
"""
import argparse
import hmac
import json
import time
from card_test import connection

AID = bytes.fromhex('a0000005272101')
ADMIN = bytes.fromhex('f000000000')


def tlv(tag, data):
    return bytes([tag, len(data)]) + data


def fields(data):
    out = []
    while data:
        tag, n = data[:2]
        assert len(data) >= n+2
        out.append((tag, data[2:n+2]))
        data = data[n+2:]
    return out



def run(card, host, touch, expected_version=None):
    checks = []
    def raw(label, apdu, status=0x9000):
        start = time.monotonic()
        data, a, b = card.transmit(apdu)
        sw = a << 8 | b
        assert sw == status, (label, f'{sw:04x}', bytes(data).hex(), f'{status:04x}')
        checks.append(dict(case=label, milliseconds=round((time.monotonic()-start)*1000, 2)))
        return bytes(data)

    def cmd(label, ins, p1=0, p2=0, data=b'', le=256, status=0x9000, cla=0):
        frame = bytes([cla, ins, p1, p2])
        if data:
            assert len(data) <= 255
            frame += bytes([len(data)]) + data
        if le is not None:
            frame += bytes([le % 256])
        return raw(label, frame, status)

    def admin():
        cmd('select_admin', 0xa4, 4, data=ADMIN)
        cmd('admin_pin', 0x20, data=b'123456', le=None)

    def select():
        data = cmd('select_oath', 0xa4, 4, data=AID)
        f = dict(fields(data))
        assert len(f[0x79]) == 3 and len(f[0x71]) == 8
        if expected_version is not None:
            assert f[0x79] == bytes(map(int, expected_version.split('.')))
        return f

    def put(name, kind, alg, key, digits=8, prop=0, counter=None, chained=False):
        body = tlv(0x71, name) + tlv(0x73, bytes([kind|alg, digits])+key)
        if prop:
            body += bytes([0x78, prop])
        if counter is not None:
            body += tlv(0x7a, counter.to_bytes(4, 'big'))
        if chained:
            cmd('put_chain_first', 1, data=body[:17], cla=0x10, le=None)
            cmd('put_chain_last', 1, data=body[17:], le=None)
        else:
            cmd('put_'+name.decode(), 1, data=body, le=None)

    def expected(alg, key, challenge, digits, truncate):
        digest = hmac.digest(key, challenge, {1:'sha1', 2:'sha256', 3:'sha512'}[alg])
        if truncate:
            off = digest[-1] & 15
            digest = (int.from_bytes(digest[off:off+4], 'big') & 0x7fffffff).to_bytes(4, 'big')
        return tlv(0x76 if truncate else 0x75, bytes([digits])+digest)

    def calculate(name, alg, key, challenge, truncate, digits=8, hotp=False):
        body = tlv(0x71, name)
        if not hotp:
            body += tlv(0x74, challenge)
        data = cmd('calculate_'+name.decode(), 0xa2, p2=int(truncate), data=body)
        assert data == expected(alg, key, challenge, digits, truncate), (name, data.hex())
        return data

    def pages(ins, p2=0, data=b'', le=100):
        frame = bytes([0, ins, 0, p2]) + (bytes([len(data)])+data if data else b'') + bytes([le])
        output = b''
        for _ in range(30):
            d, a, b = card.transmit(frame)
            sw = a << 8 | b
            assert sw in (0x9000, 0x61ff), (ins, f'{sw:04x}')
            output += bytes(d)
            checks.append(dict(case='page_'+hex(ins), bytes=len(d), sw=f'{sw:04x}'))
            if sw == 0x9000:
                return fields(output)
            assert d, 'ordinary page must make progress'
            cmd('page_requires_a5_not_get_response', 0xc0, status=0x6986)
            frame = bytes([0, 0xa5, 0, 0, le])
        raise AssertionError('pagination did not finish')

    admin()
    cmd('reset_oath', 5, le=None)
    cmd('clear_pass', 0x13, le=None)
    initial = select()
    assert 0x74 not in initial
    cmd('empty_list', 0xa1)
    keys = {1:b'12345678901234567890', 2:b'12345678901234567890123456789012', 3:b'1234567890123456789012345678901234567890123456789012345678901234'}
    entries = []
    for alg in (1, 2, 3):
        name = b'totp-'+str(alg).encode()
        put(name, 0x20, alg, keys[alg], chained=alg==3)
        entries.append((name, alg, keys[alg], 8, 0x20, 0))
        for truncate in (False, True):
            calculate(name, alg, keys[alg], (1).to_bytes(8,'big'), truncate)
    put(b'hotp', 0x10, 1, keys[1], digits=6, counter=0)
    entries.append((b'hotp',1,keys[1],6,0x10,0))
    calculate(b'hotp',1,keys[1],(1).to_bytes(8,'big'),True,6,True)
    calculate(b'hotp',1,keys[1],(2).to_bytes(8,'big'),False,6,True)
    put(b'increasing',0x20,1,keys[1],prop=1)
    entries.append((b'increasing',1,keys[1],8,0x20,1))
    calculate(b'increasing',1,keys[1],(2).to_bytes(8,'big'),True)
    calculate(b'increasing',1,keys[1],(2).to_bytes(8,'big'),True)
    cmd('calculate_all_rejects_decreasing', 0xa4, p2=1, data=tlv(0x74,(1).to_bytes(8,'big')), status=0x6982)
    calculate(b'increasing',1,keys[1],(2).to_bytes(8,'big'),True)
    put(b'touch',0x20,1,keys[1],prop=2)
    entries.append((b'touch',1,keys[1],8,0x20,2))
    if touch:
        print('Touch the CIU once when the OATH request is pending.', flush=True)
    if host or touch:
        calculate(b'touch',1,keys[1],(3).to_bytes(8,'big'),True)
    listing = pages(0xa1, le=45)
    assert listing == [(0x72, bytes([kind|alg])+name) for name,alg,key,digits,kind,prop in entries]
    for truncate in (False, True):
        result = pages(0xa4, int(truncate), tlv(0x74,(3).to_bytes(8,'big')), le=100)
        expect=[]
        for name,alg,key,digits,kind,prop in entries:
            expect.append((0x71,name))
            if kind==0x10:
                expect.append((0x77,bytes([digits])))
            elif prop&2:
                expect.append((0x7c,bytes([digits])))
            else:
                expect.extend(fields(expected(alg,key,(3).to_bytes(8,'big'),digits,truncate)))
        assert result==expect
    cmd('rename',5,data=tlv(0x71,b'totp-1')+tlv(0x71,b'renamed'),le=None)
    calculate(b'renamed',1,keys[1],(4).to_bytes(8,'big'),True)
    cmd('set_default',0x55,1,1,tlv(0x71,b'hotp'),le=None)
    if host:
        result=card.command('TOUCH 0')
        digest=hmac.digest(keys[1],(3).to_bytes(8,'big'),'sha1');off=digest[-1]&15
        assert result==f'{(int.from_bytes(digest[off:off+4],"big")&0x7fffffff)%1000000:06d}\r'.encode()
        checks.append(dict(case='pass_hotp_output',bytes=len(result)))
    # Delete clears the PASS reference before storage slots can be reused.
    cmd('delete_bound_hotp',2,data=tlv(0x71,b'hotp'),le=None)
    put(b'reused',0x10,1,keys[1],digits=6)
    admin()
    assert cmd('pass_binding_cleared',0x43)==b'\x00\x00'
    cmd('pass_hmac_config',0x44,2,0,bytes([3,20])+b'\x0b'*20,le=None)
    select()
    cmd('validate_without_access_code',0xa3,data=tlv(0x75,bytes(20))+tlv(0x74,b'hosttest'),status=0x6984)
    select()
    key=bytes(range(16));challenge=b'hosttest'
    proof=hmac.digest(key,challenge,'sha1')
    cmd('set_code',3,data=tlv(0x73,b'\x01'+key)+tlv(0x74,challenge)+tlv(0x75,proof),le=None)
    locked=select()
    assert locked[0x71]==initial[0x71] and locked[0x7b]==b'\x01'
    # Compatibility route works before OATH access-code authentication.
    assert cmd('yk_hmac_before_auth',1,0x38,data=b'Hi There')==hmac.digest(b'\x0b'*20,b'Hi There','sha1')
    assert len(cmd('yk_serial',1,0x10))==4
    cmd('locked_list',0xa1,status=0x6982)
    data=cmd('validate',0xa3,data=tlv(0x75,hmac.digest(key,locked[0x74],'sha1'))+tlv(0x74,challenge))
    assert data==tlv(0x75,proof)
    cmd('authenticated_list',0xa1)
    renewed=select()
    cmd('reselection_requires_validate',0xa1,status=0x6982)
    assert cmd('validate_renewed_challenge',0xa3,data=tlv(0x75,hmac.digest(key,renewed[0x74],'sha1'))+tlv(0x74,challenge))==tlv(0x75,proof)
    cmd('clear_code',3,data=tlv(0x73,b''),le=None)
    assert 0x74 not in select()
    if host:
        card.command('RESET')
        assert select()[0x71]==initial[0x71]
        calculate(b'renamed',1,keys[1],(5).to_bytes(8,'big'),True)
    # Common GET RESPONSE must only consume the already generated SELECT data.
    first=cmd('select_short_response',0xa4,4,data=AID,le=5,status=0x610a)
    rest=cmd('get_response',0xc0,le=10)
    assert dict(fields(first+rest))[0x71]==initial[0x71]
    for name in [b'renamed',b'totp-2',b'totp-3',b'increasing',b'touch',b'reused']:
        cmd('delete_'+name.decode(),2,data=tlv(0x71,name),le=None)
    assert cmd('empty_after_delete',0xa1)==b''
    admin()
    cmd('clear_pass_final',0x13,le=None)
    cmd('reset_oath_final',5,le=None)
    assert 0x74 not in select()
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', help='Path to oath-host executable; omit for USB DevKit')
    parser.add_argument('--touch', action='store_true', help='Also request physical touch on the USB device')
    parser.add_argument('--expected-version', help='Expected SELECT version supplied by the build profile')
    parser.add_argument('--output', help='Save JSON report')
    args=parser.parse_args()
    with connection(args.host) as card:
        checks=run(card,bool(args.host),args.touch,args.expected_version)
    report=dict(profile='rust-oath',transport='host' if args.host else 'USB',passed=len(checks),physical_touch=bool(args.touch and not args.host),checks=checks)
    output=json.dumps(report,indent=2)
    if args.output:
        with open(args.output,'w') as f:
            f.write(output+'\n')
    print(output)


if __name__=='__main__':
    main()
