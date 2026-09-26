#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the CLI contract against the real Rust engine, including slot reset."""
import subprocess
import sys

commands = [
    '0', 'zz', '00', '0' * 8200,
    '00a4040005f00000000000',
    '0020000006313233343536',
    '0043000000',
    '0044010006020361626300',
    '0043000000',
    '!POWEROFF',
    '00a4040005f00000000000',
    '0044010006020361626300',
    '0020000006313233343536',
    '0043000000',
    '!UNKNOWN',
    '00a4040008a0000006472f000100',
    '80100000010400',
    '00c0000000',
]
result = subprocess.run([sys.argv[1]], input='\n'.join(commands) + '\n',
                        text=True, capture_output=True, check=True, timeout=30)
lines = result.stdout.splitlines()
assert lines[0] == 'READY', result.stdout
replies = lines[1:]
assert len(replies) == len(commands), result.stdout
assert replies[:4] == ['ERROR invalid-hex', 'ERROR invalid-hex', 'RESP 6700', 'ERROR too-long']
assert replies[4:8] == ['RESP 9000', 'RESP 9000', 'RESP 90000000', 'RESP 9000']
assert replies[8] == 'RESP 9000020000'
assert replies[9:13] == ['OK', 'RESP 9000', 'RESP 6982', 'RESP 9000']
assert replies[13] == replies[8], 'power-off must preserve records but clear authorization'
assert replies[14] == 'ERROR unknown-control'
assert replies[15].startswith('RESP 9000'), replies[15]
assert replies[16].startswith('RESP 900000'), replies[16]
assert len(bytes.fromhex(replies[16][9:])) > 256, 'GetInfo response must traverse GET RESPONSE'
assert replies[17] == 'RESP 6986', 'automatic draining must leave no pending response'
print('Rust replay: parser recovery, authorization reset, retained records and complete GetInfo passed')
