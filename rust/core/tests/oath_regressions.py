#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Legacy OATH/PASS boundary cases against the real Rust PC/SC host engine."""
import ctypes as C
import hmac
import os
from pathlib import Path
import sys
import tempfile
from pcsc_normal import Driver
from oath_normal import tlv, fields


def run(library):
    touch_file = Path('/tmp/canokey-test-up')
    old_touch = touch_file.read_bytes() if touch_file.exists() else None
    try:
        with tempfile.TemporaryDirectory(prefix='rust-oath-regressions-') as directory:
            image = Path(directory) / 'image'
            os.environ.update(CANOKEY_VIRT_LFS_ROOT=str(image), CANOKEY_VIRT_RESET_STORAGE='1', CANOKEY_TEST_NFC='1')
            driver = Driver(library)
            assert driver.lib.IFDHCreateChannel(driver.lun, 0) == 0
            try:
                assert driver.power(500)[0] == 0
                def cmd(ins, p1=0, p2=0, data=b'', sw=0x9000, le=0):
                    request = bytes([0, ins, p1, p2]) + (bytes([len(data)]) + data if data else b'')
                    if le is not None: request += bytes([le])
                    body, a, b = driver.transmit(request)
                    assert a*256+b == sw, (request.hex(), bytes(body).hex(), hex(a*256+b), hex(sw))
                    return bytes(body)
                def admin():
                    cmd(0xa4, 4, data=bytes.fromhex('f000000000'))
                    cmd(0x20, data=b'123456', le=None)
                def oath():
                    return dict(fields(cmd(0xa4, 4, data=bytes.fromhex('a0000005272101'))))
                def put(name, kind=0x11, digits=6, key=b'12345678901234567890', extra=b'', sw=0x9000):
                    cmd(1, data=tlv(0x71, name)+tlv(0x73, bytes([kind, digits])+key)+extra, sw=sw, le=None)
                def inject():
                    cmd(0xef, data=b'03', le=None)  # Rust OATH record, single failed write.
                def calculate(name, counter, kind=0x11, sw=0x9000):
                    data=tlv(0x71,name)+(tlv(0x74,counter.to_bytes(8,'big')) if kind==0x21 else b'')
                    body=cmd(0xa2,p2=1,data=data,sw=sw)
                    if sw != 0x9000: assert body == b''
                    else:
                        digest=hmac.digest(b'12345678901234567890',counter.to_bytes(8,'big'),'sha1')
                        off=digest[-1]&15
                        assert body==tlv(0x76,b'\x06'+(int.from_bytes(digest[off:off+4],'big')&0x7fffffff).to_bytes(4,'big'))
                driver.lib.ck_core_touch.argtypes=[C.c_ubyte,C.c_void_p,C.c_size_t]
                driver.lib.ck_core_touch.restype=C.c_int32
                def touch(slot, expected=None, failure=False):
                    output=(C.c_ubyte*41)(*([0xa5]*41))
                    n=driver.lib.ck_core_touch(slot,output,33)
                    assert bytes(output[33:])==b'\xa5'*8
                    if failure:
                        assert n == -1
                    else:
                        assert n>=0
                        if expected is not None: assert bytes(output[:n])==expected,(n,bytes(output[:max(n,0)]),expected)
                    return n
                admin();cmd(5,le=None);cmd(0x13,le=None);oath()
                cmd(0xdd,sw=0x6d00)
                put(b'FH'); put(b'FH',sw=0x6985)
                inject();calculate(b'FH',1,sw=0x6900);calculate(b'FH',1);calculate(b'FH',2)
                put(b'FI',0x21,extra=b'\x78\x01')
                inject();calculate(b'FI',2,0x21,sw=0x6900);calculate(b'FI',2,0x21)
                calculate(b'FI',1,0x21,sw=0x6982);calculate(b'FI',2,0x21);calculate(b'FI',3,0x21)
                calculate(b'FI',2,0x21,sw=0x6982)
                put(b'FP');cmd(0x55,1,data=tlv(0x71,b'FP'),le=None)
                inject();touch(0,failure=True);touch(0,b'287082')
                # Counter 1..10 from RFC 4226, both PASS slots and initial counter.
                for counter, code in enumerate([b'359152',b'969429',b'338314',b'254676',b'287922',b'162583',b'399871',b'520489',b'403154'],2):
                    touch(0,code)
                cmd(2,data=tlv(0x71,b'FP'),le=None);touch(0,b'')
                put(b'initial',digits=8,extra=tlv(0x7a,(2).to_bytes(4,'big')))
                cmd(0x55,2,data=tlv(0x71,b'initial'),le=None)
                digest=hmac.digest(b'12345678901234567890',(3).to_bytes(8,'big'),'sha1');off=digest[-1]&15
                touch(1,f'{(int.from_bytes(digest[off:off+4],"big")&0x7fffffff)%100000000:08d}'.encode())
                touch(0,b'');touch(199,failure=True)
                # Literal crash-regression vectors, including incomplete counters.
                for ins,p1,data in [(1,0,'71'),(1,0,'71012073031104007a04'),(2,0,'71'),
                                    (0xa2,0,'71'),(0x55,1,'71'),(1,0,'7101007303')]:
                    cmd(ins,p1,data=bytes.fromhex(data),sw=0x6700)
                cmd(1,data=bytes.fromhex('71012073ff111000'),sw=0x6700)
                cmd(1,data=bytes.fromhex('7101207303001000'),sw=0x6a80)
                cmd(1,data=bytes.fromhex('71012073032110007a0400000000'),sw=0x6a80)
                for data in ['74','7408','740800000021060001']:
                    cmd(0xa4,p2=1,data=bytes.fromhex(data),sw=0x6700)
                for challenge in [b'',bytes(65)]:
                    cmd(0xa2,data=tlv(0x71,b'FI')+tlv(0x74,challenge),sw=0x6a80)
                # Maximum static password, append-Enter, reload and HMAC-only slots.
                admin();password=b'0123456789abcdefghijklmnopqrstuv'
                assert len(password)==32
                cmd(0x44,2,data=bytes([2,33])+password+b'x\x00',sw=0x6700,le=None)
                for enter in (0,1):
                    cmd(0x44,2,data=bytes([2,32])+password+bytes([enter]),le=None)
                    touch(1,password+(b'\r' if enter else b''))
                assert driver.power(502)[0]==0
                touch(1,password+b'\r')
                admin();key=b'\x0b'*20
                cmd(0x44,1,data=bytes([3,20])+key,le=None)
                assert cmd(0x43)[0]==3
                touch(0,b'');oath()
                for challenge in [b'Hi There',b'Hi There'+bytes(56)]:
                    assert cmd(1,0x30,data=challenge)==hmac.digest(key,challenge,'sha1')
                cmd(1,0x38,data=bytes(64),sw=0x6a82)
                assert len(cmd(1,0x10))==4
                admin();cmd(0x44,1,data=b'\x00',le=None)
                assert driver.power(502)[0]==0
                oath();cmd(1,0x30,data=bytes(64),sw=0x6a82)
                # Removing/reinserting same-sized data does not grow the live file.
                def record_size():
                    import struct
                    content=image.read_bytes();at=8+512
                    for index in range(4):
                        n=struct.unpack_from('>I',content,at)[0];at+=4
                        if index==3: return n
                        if n!=0xffffffff:at+=n
                put(b'R-0',0x21);put(b'R-1',0x21);put(b'R-2',0x21)
                before=record_size();cmd(2,data=tlv(0x71,b'R-1'),le=None)
                put(b'R-3',0x21)
                assert record_size()==before
            finally:
                assert driver.lib.IFDHCloseChannel(driver.lun)==0
    finally:
        if old_touch is None:touch_file.unlink(missing_ok=True)
        else:touch_file.write_bytes(old_touch)
    print('Rust OATH: malformed inputs, counter faults, PASS slots, HMAC, reload and record reuse passed')


if __name__=='__main__':run(sys.argv[1])
