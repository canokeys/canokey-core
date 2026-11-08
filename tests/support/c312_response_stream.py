#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse
import hashlib,json,re,subprocess
core=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description='Verify the exact pinned C response-stream generalization; preserve reviewed source patches without assigning dispositions.')
parser.add_argument('--source-repository',type=Path,required=True)
c=parser.parse_args().source_repository
assert 'reference/legacy-c' not in str(c.resolve())
def git(*a):return subprocess.check_output(['git','-C',str(c),*a])
def get(r,p):return git('show',r+':'+p).decode()
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
a=get('31e6788c^','applets/ctap/ctap.c');b=get('31e6788c','applets/ctap/ctap.c')
start=a.index('int ctap_process_pke_apdu_with_src(');end=a.index('\nint ctap_wink(',start);removed=a[start:end];a=a[:start]+a[end:]
renames=[('CTAP_MC_STREAM','CTAP_RESPONSE_STREAM'),('CTAP_make_credential_stream','CTAP_response_stream'),('ctap_make_credential_stream','ctap_response_stream'),('mc_stream_','response_stream_')]
for x,y in renames:a=a.replace(x,y)
a=a.replace('Reuse the segmented MC response engine','Reuse the segmented CTAP response engine')
b=b.replace('// Segments serve MakeCredential and largeBlobs. Construction-only storage\n// below is reused after MakeCredential has finished parsing and signing.\n','')
assert re.sub(r'\s+','',a)==re.sub(r'\s+','',b)
for path in ['applets/ctap/ctap.c','include/ctap.h']:
 assert git('show','31e6788c:'+path)==git('show','a349b268:'+path)
 assert git('diff','--unified=0','31e6788c^','31e6788c','--',path)==git('diff','--unified=0','5be9c893','a349b268','--',path)
proof=core/'docs/sync/evidence/response-stream-source-review.json'
patches=[]
for rev,parent in [('836a50a5','836a50a5^'),('31e6788c','31e6788c^'),('a349b268','5be9c893')]:
 for path in ['applets/ctap/ctap.c','include/ctap.h']:
  data=git('diff','--full-index','--unified=4',parent,rev,'--',path)
  name=f'response-stream-{rev}-{Path(path).name}.patch';(proof.parent/name).write_bytes(data)
  patches.append(dict(path='docs/sync/evidence/'+name,sha256=sha(data),commit=git('rev-parse',rev).decode().strip(),parent=git('rev-parse',parent).decode().strip(),source_path=path))
write(proof,dict(scope='Explicitly inspected C response-source aliases/cleanup and largeBlobs segmented-output changes, plus exact full-file generalization and identical final merge deltas. Not whole CTAP or response-fault/physical acceptance.',revision=git('rev-parse','a349b268').decode().strip(),patches=patches,transformation=dict(renames=renames,removed_wrapper=removed,normalization='Only whitespace after four exact identifier replacements, the displayed wrapper removal, one MC->CTAP comment change and the two inserted comment lines.',result='Full ctap.c equal; final merge file and both parent patches equal to31e6788c for both inspected paths.'),observations=[
 '836a50a5 uses the generic APDU request-source contract, zeroes all source fields, uses the shared PKE reader and closes GetInfo input before token observation/encoding on both HID/APDU paths. Rust uses one InputSource and closes before end_frame; failed-close/cancellation tests remain separately scoped.',
 '836a50a5 rejects file reads unless exactly n, and builds largeBlobs GET from a small prefix plus file segment; dispatch publishes the same response source for HID/APDU. Rust read_at is exact-or-error and Response::Blob reads the record directly. Physical storage failures and C short reads are not injected here.',
 '31e6788c changes only the listed identifiers/comments and removes the redundant PKE wrapper in these two paths. MakeCredential/file/PQ streaming continues through shared machinery; no duplicate applet/generator is required in Rust.',
 'Pinned C src/apdu.c APDU_RESPONSE_CHUNK_SIZE=250 applies to source-backed generic APDU output and GET RESPONSE. Native MSG uses the complete remaining source when it fits Le; otherwise uses that250-byte cap.',
 'Pinned C largeBlobs calls KEEPALIVE after GET offset validation and SET validation/authentication. It runs CTAPHID_Loop then processing keepalive on HID; NFC skips it. Rust now services best-effort processing progress after validation with fully owned semantic input.'
],remaining=['Negative/short storage-read injection and response close/error schedules, including certificates and generated MakeCredential/PQ output.','Review classical MC/GA/U2F Authentication and Prepared response source classification; the current250-byte cap covers GetInfo, Blob and generated Stream only. Full response-class wire matrix remains open.','Paired executing cancellation, arbitrary IRQ/endpoint faults, physical USB/RF/WTX and CIU stack/PKE acceptance.']))
print('Saved exact transformation and six inspected full-index patches')
