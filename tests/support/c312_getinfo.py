#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute pinned C GetInfo schema code with explicit configuration/storage stubs.

No firmware, filesystem or transport is emulated. The generated Rust fixtures
normalize only product identity, installed NFC and the authorized DSA44 addition.
The original C runtime assembly and CBOR integer helpers execute unchanged.
"""
import argparse
import ast
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile

REVISION = 'a349b268e12953dd85169e9649091c4f91ce7c68'
ROOT = Path(__file__).resolve().parents[2]


def source(path):
    return subprocess.check_output(['git', '-C', str(ROOT), 'show', f'{REVISION}:{path}'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/fixtures/c312-getinfo')
    args = parser.parse_args()
    from fido2 import cbor
    generator = source('scripts/gen_ctap_get_info.py')
    runtime = source('applets/ctap/ctap.c').decode()
    namespace = {'__name__': 'pinned_c_generator'}
    exec(compile(generator, f'{REVISION}:scripts/gen_ctap_get_info.py', 'exec'), namespace)
    needed = next(ast.literal_eval(n.value) for n in ast.walk(ast.parse(generator))
                  if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'needed' for t in n.targets))
    paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', REVISION], text=True).splitlines()
    headers = {p: source(p) for p in paths if p.endswith('.h')}
    with tempfile.TemporaryDirectory(prefix='c312-getinfo-') as directory:
        temp = Path(directory)
        # Firmware version comes from the pinned C product configuration.
        combined = b'\n'.join(headers.values()) + b'\n#define FIRMWARE_VERSION 312\n'
        (temp / 'constants.h').write_bytes(combined)
        constants = namespace['parse_defines']([temp / 'constants.h'], needed)
        constants['CREDENTIAL_ID_SIZE'] = 34
        types = runtime[runtime.index('typedef struct {\n  const uint8_t *buf;\n  size_t len;\n} CTAP_const_stream_segment;'):]
        types = types[:types.index('\n_Static_assert')]
        helpers = runtime[runtime.index('static void ctap_const_stream_reset('):runtime.index('static int cbor_put_bytes_header(')]
        function = runtime[runtime.index('static int ctap_prepare_get_info_stream('):]
        function = function[:function.index('\n}\n') + 3]
        preamble = '''#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#define MIN(a,b) ((a)<(b)?(a):(b))
#define CTAP1_ERR_SUCCESS 0
#define CTAP_MAX_MSG_SIZE 1296
'''
        stubs = '''
typedef struct { unsigned always_uv, force_pin_change, min_pin_length, long_touch_for_reset, max_pin_length; } CTAP_persistent_config;
static CTAP_persistent_config config;
static int configured, remaining;
static int ctap_config_load(CTAP_persistent_config *out) { *out=config; return 0; }
static int has_pin(void) { return configured; }
static int ctap_get_remaining_discoverable_credentials(void) { return remaining; }
static struct { int32_t algo_id; } ctap_sm2_attr;
static union { CTAP_const_stream_state alignment; uint8_t buffer[2048]; } applet_session_scratch;
typedef struct { size_t total_len; int (*read)(void*,uint8_t*,size_t,size_t*); void (*close)(void*); void *ctx; } CTAPHID_TxSource;
'''
        wrapper = '''
int probe(unsigned flags, int pin, unsigned minimum, unsigned used, int32_t algorithm, uint8_t *out, size_t capacity) {
  config=(CTAP_persistent_config){flags&1, (flags>>1)&1, minimum, (flags>>2)&1, 63};
  configured=pin; remaining=100-used; ctap_sm2_attr.algo_id=algorithm;
  CTAPHID_TxSource source;
  if (ctap_prepare_get_info_stream(&source) < 0) return -1;
  if (source.total_len > capacity) return -2;
  size_t written=0;
  if (source.read(source.ctx,out,capacity,&written) < 0 || written!=source.total_len) return -3;
  return (int)written;
}
'''
        vectors = []
        compiler = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
        for restricted in [False, True]:
            segments = namespace['build_segments'](constants, restricted)
            arrays = '\n'.join('static const uint8_t '+name+'[] = {'+','.join(str(b) for b in data)+'};'
                               for name, data in segments.items() if not name.endswith('_placeholder'))
            unit = preamble + f'#define CTAP_RESTRICT_ALGORITHMS {int(restricted)}\n' + types + stubs + arrays + helpers + function + wrapper
            (temp / 'probe.c').write_text(unit)
            library = temp / f'probe-{restricted}.dylib'
            subprocess.run(['cc', '-std=c11', '-O2', '-dynamiclib' if platform.system() == 'Darwin' else '-shared',
                            '-fPIC', str(temp/'probe.c'), '-o', str(library)], check=True)
            lib = ctypes.CDLL(str(library))
            lib.probe.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint, ctypes.c_uint,
                                  ctypes.c_int32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            for flags in range(8):
                for pin in [False, True]:
                    for algorithm in [-54, -257, -65537, -(1 << 31)]:
                        out = (ctypes.c_uint8 * 2048)()
                        minimum, used = (6, 2) if pin else (4, 0)
                        n = lib.probe(flags, pin, minimum, used, algorithm, out, len(out))
                        vector = dict(flags=flags, pin=pin, minimum=minimum, used=used,
                                      algorithm=algorithm, restricted=restricted, result=n)
                        if n >= 0:
                            raw = bytes(out[:n]); assert raw[0] == 0
                            decoded = cbor.decode(raw[1:]); assert len(decoded) == (22 if flags & 2 else 21)
                            vector['c_response'] = raw.hex()
                        vectors.append(vector)
        args.output.mkdir(parents=True, exist_ok=True)
        report = dict(revision=REVISION, evidence='native execution of extracted unchanged C schema function; configuration/storage stubs',
                      compiler=compiler, inputs={p: hashlib.sha256(b).hexdigest() for p,b in
                      [('scripts/gen_ctap_get_info.py',generator), ('applets/ctap/ctap.c',runtime.encode())]},
                      target_abi_limit=1296, vectors=vectors)
        (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        rust = ['// Generated by tests/support/c312_getinfo.py; pinned C schema execution.\n',
                '// Only firmware identity, installed NFC and DSA44 are normalized.\n',
                'type C312Vector = (u8, bool, u8, u8, i32, bool, bool, &\'static [u8], &\'static [u8]);\n',
                'const C312_VECTORS: &[C312Vector] = &[\n']
        for vector in vectors:
            if vector['result'] < 0:
                continue
            original = cbor.decode(bytes.fromhex(vector['c_response'])[1:])
            for nfc in [False, True]:
                expected = dict(original)
                expected[9] = ['nfc','usb'] if nfc else ['usb']
                if not vector['restricted']:
                    expected[10] = expected[10][:3] + [{'alg': -48, 'type': 'public-key'}] + expected[10][3:]
                encoded = cbor.encode(expected)
                marker = b'\x0e' + cbor.encode(312)
                assert encoded.count(marker) == 1
                before, after = encoded.split(marker)
                before += b'\x0e'
                boolean = lambda value: str(value).lower()
                rust.append('    ('+', '.join([str(vector['flags']), boolean(vector['pin']),str(vector['minimum']),
                    str(vector['used']),str(vector['algorithm']),boolean(vector['restricted']),boolean(nfc),
                    '&'+str(list(before)), '&'+str(list(after))])+'),\n')
        rust.append('];\n')
        (args.output/'vectors.rs').write_text(''.join(rust))
        print(f'Executed {len(vectors)} C states; {sum(v["result"] < 0 for v in vectors)} expected C encoding failures')


if __name__ == '__main__':
    main()
