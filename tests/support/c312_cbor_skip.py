#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the pinned C TinyCBOR unknown-value skip with its release depth limit.

Read source objects from Git into a temporary build; never compile legacy-c.
The known-parent containers model schema traversal outside cbor_value_advance.
This tests TinyCBOR's skip contract, not the complete C CTAP command parser.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CORE_REVISION = 'a349b268e12953dd85169e9649091c4f91ce7c68'
TINYCBOR_REVISION = '6442e749ca811e24afad1551338a45c75e09808f'
LIMIT = 4


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tinycbor-repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/fixtures/c312-cbor-skip')
    args = parser.parse_args()
    cmake = git(ROOT, 'show', f'{CORE_REVISION}:CMakeLists.txt')
    assert b'CBOR_PARSER_MAX_RECURSIONS=4' in cmake
    pin = git(ROOT, 'ls-tree', CORE_REVISION, 'tinycbor').decode().split()[2]
    assert pin == TINYCBOR_REVISION
    sources = ['cborparser.c', 'cbor.h', 'cborinternal_p.h',
               'cborinternalmacros_p.h', 'compilersupport_p.h', 'memory.h']
    hashes = {}
    vectors = []
    wrapper = r'''
#include "cbor.h"
int probe(const uint8_t *data, size_t length, unsigned known_parents) {
    CborParser parser;
    CborValue current, parents[3];
    CborError error = cbor_parser_init(data, length, 0, &parser, &current);
    if (error) return (int)error;
    for (unsigned i = 0; i < known_parents; ++i) {
        parents[i] = current;
        error = cbor_value_enter_container(&parents[i], &current);
        if (error) return (int)error;
    }
    error = cbor_value_advance(&current);
    if (error) return (int)error;
    for (unsigned i = known_parents; i; --i) {
        error = cbor_value_leave_container(&parents[i - 1], &current);
        if (error) return (int)error;
        current = parents[i - 1];
    }
    return cbor_value_at_end(&current) ? 0 : -1;
}
int nesting_error(void) { return CborErrorNestingTooDeep; }
'''
    with tempfile.TemporaryDirectory(prefix='c312-cbor-skip-') as directory:
        temp = Path(directory)
        for name in sources:
            path = 'src/' + name
            raw = git(args.tinycbor_repository, 'show', f'{pin}:{path}')
            (temp / name).write_bytes(raw)
            hashes[path] = hashlib.sha256(raw).hexdigest()
        (temp / 'tinycbor-export.h').write_text('#define CBOR_API\n')
        (temp / 'tinycbor-version.h').write_text(
            '#define TINYCBOR_VERSION_MAJOR 7\n#define TINYCBOR_VERSION_MINOR 0\n'
            '#define TINYCBOR_VERSION_PATCH 0\n')
        (temp / 'probe.c').write_text(wrapper)
        library = temp / 'probe.dylib'
        subprocess.run(['cc', '-std=c11', '-O2', '-fPIC', '-DCBOR_NO_FLOATING_POINT',
                        f'-DCBOR_PARSER_MAX_RECURSIONS={LIMIT}',
                        '-dynamiclib' if platform.system() == 'Darwin' else '-shared',
                        str(temp / 'cborparser.c'), str(temp / 'probe.c'),
                        '-o', str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.probe.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint]
        nesting_error = lib.nesting_error()
        leaves = [b'\x00', b'\x78\x46' + b'x' * 70,
                  b'\x59\x01\x00' + bytes(range(256))]
        for shape in ['array', 'map', 'mixed']:
            for depth in [0, 1, 3, 4, 5, 8, 9]:
                for leaf in leaves:
                    value = leaf
                    for level in range(depth):
                        value = (b'\xa1\x00' if shape == 'map' or
                                 (shape == 'mixed' and level % 2) else b'\x81') + value
                    results = []
                    for parents in range(4):
                        wire = b'\x81' * parents + value
                        data = (ctypes.c_uint8 * len(wire)).from_buffer_copy(wire)
                        result = lib.probe(data, len(wire), parents)
                        assert result == (0 if depth <= LIMIT else nesting_error)
                        results.append(result)
                    vectors.append(dict(shape=shape, depth=depth, value=value.hex(),
                                        accepted=results[0] == 0, known_parent_results=results))
    args.output.mkdir(parents=True, exist_ok=True)
    report = dict(core_revision=CORE_REVISION, tinycbor_revision=pin,
                  evidence='Native execution of pinned TinyCBOR skip; no C CTAP/transport execution',
                  max_unknown_containers=LIMIT, inputs=hashes,
                  nesting_error=nesting_error, executions=len(vectors) * 4, vectors=vectors)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    rust = ['// Generated by tests/support/c312_cbor_skip.py; pinned C execution oracle.',
            'const C312_UNKNOWN_VALUES: &[(&[u8], bool)] = &[']
    for vector in vectors:
        literal = ''.join(f'\\x{byte:02x}' for byte in bytes.fromhex(vector['value']))
        rust.append(f'    (b"{literal}", {str(vector["accepted"]).lower()}),')
    rust.append('];\n')
    (args.output / 'vectors.rs').write_text('\n'.join(rust))
    print(f'TinyCBOR: {len(vectors)} values, {len(vectors) * 4} executions, limit={LIMIT}')


if __name__ == '__main__':
    main()
