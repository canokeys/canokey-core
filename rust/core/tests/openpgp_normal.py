#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normal OpenPGP flows with independent host verification, also usable over USB.
Dedicated device only: resets OpenPGP, writes throwaway keys and restores default
OpenPGP state on successful completion. Other applets are not reset. A failure
leaves test state for inspection; rerun requires the default OpenPGP PW3.
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from oath_normal import connection
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519, padding, utils
AID=bytes.fromhex('d27600012401')
REF=[0xb6,0xb8,0xa4]
ATTR=[bytes.fromhex(s) for s in ['132a8648ce3d030107','132b8104000a','132b81040022','162b06010401da470f01','122b060104019755010501','010800002002','010c00002002','011000002002','132b81040023']]
CURVES={0:ec.SECP256R1,1:ec.SECP256K1,2:ec.SECP384R1,8:ec.SECP521R1}
def length(n):
    return bytes([n]) if n<128 else bytes([0x81,n]) if n<256 else b'\x82'+n.to_bytes(2,'big')
def tlv(t,b):return t.to_bytes(1 if t<256 else 2,'big')+length(len(b))+b
def fields(b):
    out={}
    while b:
        t=b[0];i=1
        if t&31==31:t=(t<<8)|b[i];i+=1
        n=b[i];i+=1
        if n&128:k=n&127;n=int.from_bytes(b[i:i+k],'big');i+=k
        assert len(b)>=i+n
        out[t]=b[i:i+n];b=b[i+n:]
    return out
class Card:
    def __init__(self,wire):self.wire=wire;self.checks=[]
    def cmd(self,label,ins,p1=0,p2=0,data=b'',le=256,cla=0,status=0x9000):
        start=time.monotonic();chunks=[data[i:i+193] for i in range(0,len(data),193)] or [b''];answer=b''
        for i,b in enumerate(chunks):
            last=i==len(chunks)-1
            apdu=bytes([cla if last else 0x10,ins,p1,p2])+(bytes([len(b)])+b if b else b'')
            if last and le is not None:apdu+=bytes([le%256])
            part,a,z=self.wire.transmit(apdu);sw=a<<8|z
            if not last:assert sw==0x9000,(label,'chain',hex(sw))
            else:answer=bytes(part)
        while sw>>8==0x61:
            part,a,z=self.wire.transmit(bytes([0,0xc0,0,0,0]));answer+=bytes(part);sw=a<<8|z
        assert sw==status,(label,hex(sw),hex(status),answer.hex())
        self.checks.append(dict(case=label,milliseconds=round((time.monotonic()-start)*1000,2)))
        return answer
    def select(self):return self.cmd('select',0xa4,4,data=AID)
    def verify(self,mode=0x83,value=None):return self.cmd('verify',0x20,0,mode,value or (b'12345678' if mode==0x83 else b'123456'),le=None)
    def get(self,tag):return self.cmd(f'get_{tag:04x}',0xca,tag>>8,tag&255)
    def put(self,tag,b):return self.cmd(f'put_{tag:04x}',0xda,tag>>8,tag&255,b,le=None)
    def reset(self):self.select();self.verify();self.cmd('terminate',0xe6,le=None);self.cmd('activate',0x44,le=None);self.select();self.verify()
    def attrs(self,alg,role):
        a=ATTR[alg]
        if role==1 and alg in CURVES:a=b'\x12'+a[1:]
        self.put(0xc1+role,a)
    def public(self,role,generate=False):return fields(self.cmd('generate' if generate else 'public',0x47,0x80 if generate else 0x81,data=bytes([REF[role],0])))[0x7f49]
    def import_key(self,alg,role,key):
        if alg in (5,6,7):
            v=key.private_numbers();width=key.key_size//16
            parts=[v.public_numbers.e.to_bytes(4,'big')]+[x.to_bytes(width,'big') for x in [v.p,v.q,v.iqmp,v.dmp1,v.dmq1]]
            tags=[0x91,0x92,0x93,0x94,0x95,0x96]
        else:
            if alg in CURVES:value=key.private_numbers().private_value.to_bytes((key.curve.key_size+7)//8,'big')
            else:value=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
            parts=[value];tags=[0x92]
        descriptors=b''.join(bytes([t])+length(len(v)) for t,v in zip(tags,parts))
        body=bytes([REF[role],0])+tlv(0x7f48,descriptors)+tlv(0x5f48,b''.join(parts))
        self.cmd('import',0xdb,0x3f,0xff,tlv(0x4d,body),le=None)
def pubkey(alg,wire):
    f=fields(wire)
    if alg in (5,6,7):return rsa.RSAPublicNumbers(int.from_bytes(f[0x82],'big'),int.from_bytes(f[0x81],'big')).public_key()
    if alg in CURVES:return ec.EllipticCurvePublicKey.from_encoded_point(CURVES[alg](),f[0x86])
    return (ed25519.Ed25519PublicKey if alg==3 else x25519.X25519PublicKey).from_public_bytes(f[0x86])
def exercise(c,alg,role,key):
    c.verify(0x81 if role==0 else 0x82)
    if role!=1:
        message=b'Rust OpenPGP normal operation'
        if alg in (5,6,7):value=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(message).digest()
        elif alg in CURVES:value=hashlib.sha256(message).digest()
        else:value=message
        sig=c.cmd('sign',0x2a if role==0 else 0x88,0x9e if role==0 else 0,0x9a if role==0 else 0,value)
        if alg in (5,6,7):key.verify(sig,message,padding.PKCS1v15(),hashes.SHA256())
        elif alg in CURVES:
            width=len(sig)//2;key.verify(utils.encode_dss_signature(int.from_bytes(sig[:width],'big'),int.from_bytes(sig[width:],'big')),message,ec.ECDSA(hashes.SHA256()))
        else:key.verify(sig,message)
    else:
        if alg in (5,6,7):expected=b'OpenPGP decrypted message';value=b'\x00'+key.encrypt(expected,padding.PKCS1v15())
        else:
            peer=x25519.X25519PrivateKey.generate() if alg==4 else ec.generate_private_key(CURVES[alg]())
            if alg==4:point=peer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw);expected=peer.exchange(key)
            else:point=peer.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint);expected=peer.exchange(ec.ECDH(),key)
            value=tlv(0xa6,tlv(0x7f49,tlv(0x86,point)))
        assert c.cmd('decipher',0x2a,0x80,0x86,value)==expected

def run(wire,host):
    c=Card(wire);c.reset()
    assert c.get(0x4f)[:6]==AID
    assert len(c.get(0xc4))==7
    assert len(fields(fields(c.get(0xfa))[0xfa]))==3
    for tag,b in [(0x5b,b'Doe<<Jane'),(0x5e,b'jane'),(0x5f2d,b'en'),(0x5f35,b'2'),(0x5f50,b'https://example.org/key')]:c.put(tag,b);assert c.get(tag)==b
    assert fields(fields(c.get(0x65))[0x65])[0x5b]==b'Doe<<Jane'
    assert fields(fields(c.get(0x6e))[0x6e])[0x4f][:6]==AID
    for r in range(3):
        cert=bytes((i+r)%256 for i in range(1024))
        c.cmd('select_cert',0xa5,r,4,bytes.fromhex('60045c027f21'),le=None);c.put(0x7f21,cert)
        c.cmd('select_cert_read',0xa5,r,4,bytes.fromhex('60045c027f21'),le=None);assert c.get(0x7f21)==cert
        c.put(0xc7+r,bytes([r+1])*20);c.put(0xce+r,bytes([r+1])*4)
    assert len(c.get(0xc5))==60 and len(c.get(0xcd))==12
    c.cmd('change_pw1',0x24,0,0x81,b'123456654321',le=None);c.verify(0x82,b'654321')
    c.put(0xd3,b'87654321');c.cmd('reset_pw1_rc',0x2c,0,0x81,b'87654321123456',le=None);c.verify(0x82)
    c.cmd('change_pw3',0x24,0,0x83,b'1234567887654321',le=None);c.verify(0x83,b'87654321')
    c.cmd('restore_pw3',0x24,0,0x83,b'8765432112345678',le=None);c.verify()
    assert len(c.cmd('challenge',0x84,le=32))==32
    for alg in range(9):
        for role in range(3):
            if alg==3 and role==1 or alg==4 and role!=1:continue
            c.attrs(alg,role)
            # Generate once per algorithm; import independently generated keys for
            # every role, including multi-APDU RSA-4096 component templates.
            if role==(1 if alg==4 else 0):
                key=pubkey(alg,c.public(role,True));exercise(c,alg,role,key)
            if alg in (5,6,7):private=rsa.generate_private_key(65537,(alg-3)*1024)
            elif alg in CURVES:private=ec.generate_private_key(CURVES[alg]())
            elif alg==3:private=ed25519.Ed25519PrivateKey.generate()
            else:private=x25519.X25519PrivateKey.generate()
            c.import_key(alg,role,private)
            actual=pubkey(alg,c.public(role)).public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            assert actual==private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            exercise(c,alg,role,private.public_key())
        print(f'OpenPGP algorithm {alg}: generate/import/use passed',file=sys.stderr,flush=True)
    # Re-selection retains current grants; real reset clears session grants and
    # reloads persistent metadata/keys. No boundary or fault-injection tests.
    c.select();c.cmd('reselect_preserves_mode82',0x20,0,0x82,le=None);c.get(0xc1)
    c.verify();c.cmd('reset_pw1_admin',0x2c,2,0x81,b'123456',le=None);c.verify(0x81)
    c.cmd('set_retry_limits',0xf2,data=bytes([3,3,3]),le=None);c.verify()
    if host:
        c.attrs(0,0);key=pubkey(0,c.public(0,True));c.put(0xd6,bytes([1,0x20]))
        exercise(c,0,0,key);c.put(0xd6,bytes([0,0x20]))

    if host:
        wire.command('RESET');c.select();c.verify(0x81);c.public(0)
    c.reset()
    c.cmd('select_admin_reset',0xa4,4,data=bytes.fromhex('f000000000'))
    c.cmd('verify_admin_reset',0x20,data=b'123456',le=None)
    c.cmd('admin_reset_openpgp',3,le=None)
    c.select();assert c.get(0xde)==bytes([1,0,2,0,3,0])
    return {'checks':len(c.checks),'cases':c.checks,'result':'pass'}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--host');a.add_argument('--output');args=a.parse_args()
    with connection(args.host) as wire:report=run(wire,bool(args.host))
    if args.output:Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'checks':report['checks'],'result':report['result']}))
