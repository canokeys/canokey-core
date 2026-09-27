#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run an isolated pcscd and python-fido2 client against the Rust IFD library.

pcscd must be built with --enable-ipcdir=<the supplied private directory>.
This test never starts/stops the system daemon or writes a system reader config.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

CLIENT = '''
import time, hashlib
from smartcard.System import readers
from fido2.pcsc import CtapPcscDevice
from fido2.ctap2 import Ctap2
for _ in range(50):
    available = readers()
    if available:
        break
    time.sleep(.1)
assert len(available) == 1, available
print("Reader:", available[0])
with next(CtapPcscDevice.list_devices()) as device:
    # Keep the client's default NFCCTAP_MSG P1=80 and short APDU framing.
    ctap = Ctap2(device)
    info = ctap.get_info()
    assert info.options["credMgmt"] and info.options["largeBlobs"]
    digest = hashlib.sha256(b"pcscd live credential").digest()
    result = ctap.make_credential(digest, {"id":"live-pcsc.example"},
        {"id":b"live-user"}, [{"type":"public-key","alg":-7}], options={"rk":True})
    answer = ctap.get_assertion("live-pcsc.example", digest, options={"up":False})
    result.auth_data.credential_data.public_key.verify(bytes(answer.auth_data)+digest,answer.signature)
    assert answer.credential["id"] == result.auth_data.credential_data.credential_id
print("Live pcscd/python-fido2: GetInfo, resident credential and independently verified assertion passed")
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True, type=Path)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--ipc-dir', required=True, type=Path)
    parser.add_argument('--client-library-dir', type=Path)
    parser.add_argument('--log', required=True, type=Path)
    args = parser.parse_args()
    ipc = args.ipc_dir.resolve()
    if ipc == Path('/run/pcscd') or ipc == Path('/var/run/pcscd'):
        parser.error('use a private IPC directory, not the system daemon path')
    if (ipc/'pcscd.comm').exists() or (ipc/'pcscd.pid').exists():
        parser.error('private IPC directory is already active or needs cleanup')
    # pcscd prints its build configuration on --version, including the IPC path.
    version = subprocess.run([str(args.daemon), '--version'], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True).stdout
    if f'ipcdir={ipc}' not in version.split():
        parser.error('pcscd was not compiled with the supplied private --enable-ipcdir')
    touch = Path('/tmp/canokey-test-up')
    saved = touch.read_bytes() if touch.exists() else None
    try:
        with tempfile.TemporaryDirectory(prefix='rust-pcsc-daemon-', dir='/tmp') as directory:
            work = Path(directory)
            (work/'readers').mkdir()
            library = args.library.resolve()
            if any(c in str(library) for c in '\n\r"'):
                parser.error('unsupported library path in reader configuration')
            driver = work/'driver.so'
            driver.symlink_to(library)
            (work/'readers'/'virtual.conf').write_text(
                f'FRIENDLYNAME "Rust CanoKey"\nDEVICENAME /dev/null\nLIBPATH {driver}\nCHANNELID 1\n')
            env = dict(os.environ, CANOKEY_VIRT_LFS_ROOT=str(work/'image'),
                       CANOKEY_VIRT_RESET_STORAGE='1', CANOKEY_TEST_NFC='1',
                       PCSCLITE_CSOCK_NAME=str(ipc/'pcscd.comm'))
            if args.client_library_dir:
                env['LD_LIBRARY_PATH'] = str(args.client_library_dir.resolve()) + ':' + env.get('LD_LIBRARY_PATH', '')
            touch.write_text('0\n')
            with args.log.open('w') as log:
                daemon = subprocess.Popen([str(args.daemon), '-f', '-d', '--disable-polkit',
                    '-c', str(work/'readers')], env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    for _ in range(100):
                        if daemon.poll() is not None:
                            raise RuntimeError(f'pcscd exited with {daemon.returncode}; see {args.log}')
                        if (ipc/'pcscd.comm').exists():
                            break
                        time.sleep(.05)
                    else:
                        raise RuntimeError('pcscd did not create its private socket')
                    subprocess.run([sys.executable, '-c', CLIENT], env=env, check=True, timeout=25)
                finally:
                    if daemon.poll() is None:
                        daemon.terminate()
                    try:
                        daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait()
    finally:
        if saved is None:
            touch.unlink(missing_ok=True)
        else:
            touch.write_bytes(saved)

if __name__ == '__main__':
    main()
