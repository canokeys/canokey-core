#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADMIN/CTAP integration, including literal BE32 configuration wire values."""
import argparse
import hashlib
from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData
from fido2.ctap2.pin import PinProtocolV1
from card_test import Card, connection
from ctap_fixture import provision, mixed_management


def run(wire):
    card = Card(wire)
    verify_attestation = provision(card)
    wire.command("RESET")
    def admin():
        card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    def fido():
        card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001"))
    def call(command, params=None, status=0):
        data = bytes([command]) + (cbor.encode(params) if params is not None else b"")
        out = card.cmd("ctap", 0x10, cla=0x80, data=data)
        assert out[0] == status, out.hex()
        result = cbor.decode(out[1:]) if len(out) > 1 else {}
        if command == 10 and len(out) > 1:
            assert cbor.encode(result) == out[1:], "complete canonical management response"
        return result
    admin()
    card.cmd("unauthorized", 0x12, data=bytes.fromhex("ffff0000fffeffff"), status=0x6982)
    card.cmd("verify", 0x20, data=b"123456")
    default = bytes.fromhex("00000009ffffffca")
    assert card.cmd("read default", 0x11) == default
    # Every reserved curve and algorithm from the legacy ADMIN policy.
    for curve in [*range(9), 256, 257, 258, 259]:
        invalid = curve.to_bytes(4, "big", signed=True) + default[4:]
        card.cmd("reserved curve", 0x12, data=invalid, status=0x6a80)
        assert card.cmd("unchanged after invalid curve", 0x11) == default
    for algorithm in [-7, -8, -49]:
        invalid = default[:4] + algorithm.to_bytes(4, "big", signed=True)
        card.cmd("reserved algorithm", 0x12, data=invalid, status=0x6a80)
        assert card.cmd("unchanged after invalid algorithm", 0x11) == default
    for curve in [9, 23, 24, 255, 260, -1, -65536, -65537, -(1 << 31), (1 << 31)-1]:
        config = curve.to_bytes(4, "big", signed=True) + default[4:]
        card.cmd("allowed curve", 0x12, data=config)
        assert card.cmd("curve readback", 0x11) == config
    for encoded, algorithm in [
        ("00000009ffffffca", -54),
        ("01234567fedcba98", -19088744),
        ("800000007fffffff", 2147483647),
        ("7fffffff80000000", -2147483648),
    ]:
        config = bytes.fromhex(encoded)
        card.cmd("literal wire config", 0x12, data=config)
        wire.command("RESET")
        admin()
        card.cmd("read requires grant", 0x11, status=0x6982)
        card.cmd("verify", 0x20, data=b"123456")
        assert card.cmd("reload literal bytes", 0x11) == config
        for size in [7, 9]:
            card.cmd("invalid config size", 0x12, data=bytes(size), status=0x6700)
            assert card.cmd("unchanged after invalid size", 0x11) == config
        fido()
        assert [a["alg"] for a in call(4)[10]] == [-7, -8, algorithm, -49]
        mixed_management(call, verify_attestation, int.from_bytes(config[:4], "big", signed=True), algorithm)
        admin()
        card.cmd("verify", 0x20, data=b"123456")
    # Certificate provisioning above traverses multiple ISO command fragments;
    # other ADMIN commands must not silently accept the chaining class bit.
    card.raw("version cannot chain", 0x31, cla=0x10, status=0x6e00)
    custom = bytes.fromhex("ffff0000fffeffff") # curve -65536, algorithm -65537
    card.cmd("configure", 0x12, data=custom)
    assert card.cmd("read custom", 0x11) == custom
    assert wire.command("SIZE 181") == bytes.fromhex("00000008")
    wire.command("RESET")
    fido()
    info = call(4)
    assert [a["alg"] for a in info[10]] == [-7, -8, -65537, -49]
    request = {1: hashlib.sha256(b"test").digest(), 2: {"id": "example.com"}, 3: {"id": b"user"},
               4: [{"type": "public-key", "alg": -54}]}
    call(1, request, 0x26)
    request[4] = [{"type": "public-key", "alg": -999}, {"type": "public-key", "alg": -65537}, {"type": "public-key", "alg": -7}]
    result = call(1, request)
    key = AuthenticatorData(result[2]).credential_data.public_key
    assert key[3] == -65537 and key[-1] == -65536
    verify_attestation(result, request[1])
    handle = {"id": AuthenticatorData(result[2]).credential_data.credential_id, "type": "public-key"}
    call(2, {1: "example.com", 2: request[1], 3: [handle]})
    call(7) # Credential reset preserves provisioned SM2 identifiers.
    retired = dict(handle)
    call(2, {1: "example.com", 2: request[1], 3: [retired]}, 0x2e)
    assert [a["alg"] for a in call(4)[10]] == [-7, -8, -65537, -49]
    # Factory recovery also revokes CTAP credentials, but retains manufacturing material.
    result = call(1, request)
    verify_attestation(result, request[1])
    call(2, {1: "example.com", 2: request[1], 3: [retired]}, 0x2e)
    handle["id"] = AuthenticatorData(result[2]).credential_data.credential_id
    admin()
    for status in (0x63c2, 0x63c1, 0x6983):
        card.cmd("block admin", 0x20, data=b"wrong!", status=status)
    card.cmd("factory reset", 0x50, data=b"RESET")
    fido()
    call(2, {1: "example.com", 2: request[1], 3: [handle]}, 0x2e)
    assert [a["alg"] for a in call(4)[10]] == [-7, -8, -65537, -49]
    verify_attestation(call(1, request), request[1])
    wire.command("FAIL_READ 182")
    call(1, request, 0x7f)
    card.cmd("no partial failed-read attestation", 0xc0, status=0x6986)
    verify_attestation(call(1, request), request[1])
    admin()
    card.cmd("verify", 0x20, data=b"123456")
    card.cmd("restore", 0x12, data=default)
    card.cmd("empty attestation certificate", 2, data=b"")
    fido()
    for algorithm in [-7, -49]:
        call(1, request | {4: [{"type": "public-key", "alg": algorithm}]}, 0x7f)
        card.cmd("no partial attestation", 0xc0, status=0x6986)
    verify_attestation = provision(card)
    fido()
    for algorithm in [-7, -49]:
        verify_attestation(call(1, request | {4: [{"type": "public-key", "alg": algorithm}]}), request[1])
    print(f"CTAP configuration: {len(card.checks)} checks passed")


def boot_rebuild(wire, damage):
    # Fresh device per case: never extend the protocol's ten-second reset gate.
    card = Card(wire)
    default = bytes.fromhex("00000009ffffffca")
    request = {1: hashlib.sha256(b"boot rebuild").digest()}
    def admin():
        card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    def fido():
        card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001"))
    def call(command, params=None, status=0):
        out = card.cmd("ctap", 0x10, cla=0x80,
                       data=bytes([command]) + (cbor.encode(params) if params is not None else b""))
        assert out[0] == status, out.hex()
        return cbor.decode(out[1:]) if len(out) > 1 else {}
    verify_attestation = provision(card)
    admin()
    card.cmd("verify", 0x20, data=b"123456")
    custom = bytes.fromhex("800000007fffffff")
    card.cmd("custom SM2 before rebuild", 0x12, data=custom)
    fido()
    registration = {1: request[1], 2: {"id": "boot.example"}, 3: {"id": b"boot"},
                    4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
    made = call(1, registration)
    verify_attestation(made, request[1])
    credential = AuthenticatorData(made[2]).credential_data
    descriptor = {"id": credential.credential_id, "type": "public-key"}
    protocol = PinProtocolV1()
    public, secret = protocol.encapsulate(call(6, {1: 1, 2: 2})[1])
    encrypted = protocol.encrypt(secret, b"12345678".ljust(64, b"\0"))
    call(6, {1: 1, 2: 3, 3: public, 4: protocol.authenticate(secret, encrypted), 5: encrypted})
    records = {record: wire.command(f"RECORD {record}") for record in (77, 78, 79, 80, 181, 182)}
    if damage == "missing-key":
        wire.command("FAIL_READ 182")
        assert wire.command("TRY_RESET") == bytes.fromhex("ffffffff")
        for record, value in records.items():
            assert wire.command(f"RECORD {record}") == value, "read error must not rebuild"
    wire.command("RESET")
    fido()
    assert call(4)[4]["clientPin"] is True
    assertion = {1: "boot.example", 2: request[1], 3: [descriptor]}
    signed = call(2, assertion)
    credential.public_key.verify(signed[2] + request[1], signed[3])
    if damage == "missing-key":
        wire.command("REMOVE 182")
        wire.command("FAIL_WRITE 80")
        assert wire.command("TRY_RESET") == bytes.fromhex("ffffffff")
        assert wire.command("RECORD 80") == records[80]
    elif damage == "short-key":
        wire.command(f"RECORD 182 {records[182][:-3].hex()}")
    elif damage == "empty-cert":
        wire.command("RECORD 183 ")
    else:
        wire.command("RECORD 181 00000001ffffffca")
    wire.command("RESET")
    for record in (77, 78, 79, 80, 180):
        assert wire.command(f"SIZE {record}") == bytes.fromhex("ffffffff")
    admin()
    card.cmd("verify", 0x20, data=b"123456")
    assert card.cmd("SM2 after rebuild", 0x11) == (default if damage == "invalid-sm2" else custom)
    fido()
    assert call(4)[4]["clientPin"] is False
    call(2, assertion, 0x2e)
    verify_attestation = provision(card)
    fido()
    made = call(1, registration | {7: {"rk": False}})
    verify_attestation(made, request[1])
    assert AuthenticatorData(made[2]).counter == 1
    call(2, assertion, 0x2e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    with connection(args.host) as wire:
        run(wire)
    for damage in ("missing-key", "short-key", "empty-cert", "invalid-sm2"):
        with connection(args.host) as wire:
            boot_rebuild(wire, damage)
