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
        card.cmd("fido", 0xa4, 4, data=bytes.fromhex("f043414e4f464944"))
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
    for algorithm in [-7, -8, -49, -48]:
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
        assert [a["alg"] for a in call(4)[10]] == [-7, -8, -49, -48, algorithm]
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
    assert [a["alg"] for a in info[10]] == [-7, -8, -49, -48, -65537]
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
    assert [a["alg"] for a in call(4)[10]] == [-7, -8, -49, -48, -65537]
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
    assert [a["alg"] for a in call(4)[10]] == [-7, -8, -49, -48, -65537]
    verify_attestation(call(1, request), request[1])
    wire.command("FAIL_READ 182")
    call(1, request, 0x7f)
    card.cmd("no partial failed-read attestation", 0xc0, status=0x6986)
    verify_attestation(call(1, request), request[1])
    admin()
    card.cmd("verify", 0x20, data=b"123456")
    card.cmd("restore", 0x12, data=default)
    # Manufacturing record IDs from the compact CTAP storage ABI.
    key_record = 182
    certificate_record = 183
    saved_key = wire.command(f"RECORD {key_record}")[:-2]
    assert len(saved_key) == 32
    fido()
    saved_certificate = call(1, request)[3]["x5c"][0]
    for damaged_key in [None, saved_key[:-1]]:
        if damaged_key is None:
            wire.command(f"REMOVE {key_record}")
        else:
            wire.command(f"RECORD {key_record} {damaged_key.hex()}")
        for algorithm in [-7, -8, -49, -48]:
            call(1, request | {4: [{"type": "public-key", "alg": algorithm}]}, 0x7f)
            card.cmd("no fallback on missing or short key", 0xc0, status=0x6986)
    wire.command(f"RECORD {key_record} {saved_key.hex()}")
    for certificate in [b"", None]:
        if certificate is None:
            wire.command(f"REMOVE {certificate_record}")
        else:
            wire.command(f"RECORD {certificate_record} {certificate.hex()}")
        # This one-shot read fault must survive self attestation and strict-PQ
        # certificate rejection: neither path may read the provisioned key.
        wire.command(f"FAIL_READ {key_record}")
        for algorithm in [-7, -8]:
            result = call(1, request | {4: [{"type": "public-key", "alg": algorithm}]})
            assert result[1] == "packed"
            assert set(result[3]) == {"alg", "sig"}
            assert result[3]["alg"] == algorithm
            credential = AuthenticatorData(result[2]).credential_data
            credential.public_key.verify(result[2] + request[1], result[3]["sig"])
        for algorithm in [-49, -48]:
            call(1, request | {4: [{"type": "public-key", "alg": algorithm}]}, 0x7f)
            card.cmd("strict PQ needs a certificate", 0xc0, status=0x6986)
        admin()
        card.cmd("verify before certificate restore", 0x20, data=b"123456")
        card.cmd("restore certificate through ISO chaining", 2, data=saved_certificate)
        fido()
        es256 = request | {4: [{"type": "public-key", "alg": -7}]}
        call(1, es256, 0x7f)  # The unconsumed one-shot private-key fault.
        card.cmd("no partial failed-read attestation", 0xc0, status=0x6986)
        verify_attestation(call(1, es256), request[1])
    for algorithm in [-7, -8, -49, -48]:
        verify_attestation(call(1, request | {4: [{"type": "public-key", "alg": algorithm}]}), request[1])
    print(f"CTAP configuration: {len(card.checks)} checks passed")


# Compact CTAP storage ABI: PIN, master, counter, 25 resident groups, blob,
# SM2 settings, attestation private key and certificate. IDs are fixture inputs.
PIN_RECORD = 0x4d
MASTER_RECORD = 0x4e
COUNTER_RECORD = 0x4f
GROUP_BASE = 0x50
GROUP_COUNT = 25
BLOB_RECORD = 0xb4
SM2_RECORD = 0xb5
KEY_RECORD = 0xb6
CERTIFICATE_RECORD = 0xb7
BOOT_CASES = (
    "missing-key", "short-key", "empty-cert", "missing-cert", "malformed-cert", "key-io",
    "missing-sm2", "short-sm2", "invalid-sm2", "sm2-io",
    "unprovisioned-es256", "unprovisioned-ed25519",
)


def boot_preserves(wire, damage):
    card = Card(wire)
    default = bytes.fromhex("00000009ffffffca")
    custom = bytes.fromhex("800000007fffffff")
    client_hash = hashlib.sha256(b"boot preservation").digest()
    unprovisioned = damage.startswith("unprovisioned-")
    algorithm = -8 if damage == "unprovisioned-ed25519" else -7
    def admin():
        card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    def fido():
        card.cmd("fido", 0xa4, 4, data=bytes.fromhex("f043414e4f464944"))
    def call(command, params=None, status=0x00):
        out = card.cmd("ctap", 0x10, cla=0x80,
                       data=bytes([command]) + (cbor.encode(params) if params is not None else b""))
        assert out[0] == status, (damage, out.hex())
        return cbor.decode(out[1:]) if len(out) > 1 else {}
    def snapshot():
        records = {}
        for record in (PIN_RECORD, MASTER_RECORD, COUNTER_RECORD,
                       *range(GROUP_BASE, GROUP_BASE + GROUP_COUNT), BLOB_RECORD):
            size = wire.command(f"SIZE {record}")
            value = None if size == bytes.fromhex("ffffffff") else wire.command(f"RECORD {record}")
            records[record] = size, value
        return records
    verify_attestation = provision(card)
    saved_key = wire.command(f"RECORD {KEY_RECORD}")[:-2]
    assert len(saved_key) == 32
    admin()
    card.cmd("verify", 0x20, data=b"123456")
    card.cmd("custom SM2 before reboot", 0x12, data=custom)
    if unprovisioned:
        for record in (KEY_RECORD, CERTIFICATE_RECORD, SM2_RECORD):
            wire.command(f"REMOVE {record}")
    fido()
    registration = {1: client_hash, 2: {"id": "boot.example"}, 3: {"id": b"boot"},
                    4: [{"type": "public-key", "alg": algorithm}], 7: {"rk": True}}
    made = call(1, registration)
    credential = AuthenticatorData(made[2]).credential_data
    if unprovisioned:
        assert set(made[3]) == {"alg", "sig"}
        credential.public_key.verify(made[2] + client_hash, made[3]["sig"])
        saved_certificate = None
    else:
        verify_attestation(made, client_hash)
        saved_certificate = made[3]["x5c"][0]
    descriptor = {"id": credential.credential_id, "type": "public-key"}
    assertion = {1: "boot.example", 2: client_hash, 3: [descriptor]}
    protocol = PinProtocolV1()
    public, secret = protocol.encapsulate(call(6, {1: 1, 2: 2})[1])
    encrypted = protocol.encrypt(secret, b"12345678".ljust(64, b"\0"))
    call(6, {1: 1, 2: 3, 3: public, 4: protocol.authenticate(secret, encrypted), 5: encrypted})
    # Valid empty largeBlob array and its CTAP 2.1 truncated SHA-256 checksum.
    blob = b"\x80"
    blob += hashlib.sha256(blob).digest()[:16]
    wire.command(f"RECORD {BLOB_RECORD} {blob.hex()}")
    before = snapshot()
    if damage == "missing-key":
        wire.command(f"REMOVE {KEY_RECORD}")
    elif damage == "short-key":
        wire.command(f"RECORD {KEY_RECORD} {saved_key[:-1].hex()}")
    elif damage == "empty-cert":
        wire.command(f"RECORD {CERTIFICATE_RECORD} ")
    elif damage == "missing-cert":
        wire.command(f"REMOVE {CERTIFICATE_RECORD}")
    elif damage == "malformed-cert":
        # Incomplete DER SEQUENCE: startup cannot authorize credential erasure
        # from certificate contents, regardless of command-time DER handling.
        wire.command(f"RECORD {CERTIFICATE_RECORD} 30")
    elif damage == "missing-sm2":
        wire.command(f"REMOVE {SM2_RECORD}")
    elif damage == "short-sm2":
        wire.command(f"RECORD {SM2_RECORD} {custom[:-1].hex()}")
    elif damage == "invalid-sm2":
        wire.command(f"RECORD {SM2_RECORD} 00000001ffffffca")
    elif damage == "key-io":
        wire.command(f"FAIL_READ {KEY_RECORD}")
    elif damage == "sm2-io":
        wire.command(f"FAIL_READ {SM2_RECORD}")
    material_sizes = {record: wire.command(f"SIZE {record}")
                      for record in (SM2_RECORD, KEY_RECORD, CERTIFICATE_RECORD)}
    # Repeated boots must neither consume manufacturing read faults nor write
    # or erase CTAP records. Include every resident group, even absent groups.
    for _ in range(2):
        assert wire.command("TRY_RESET") == bytes.fromhex("00000000"), damage
        assert snapshot() == before, damage
        for record, size in material_sizes.items():
            assert wire.command(f"SIZE {record}") == size, damage
    fido()
    if damage in ("short-sm2", "invalid-sm2", "sm2-io"):
        call(4, status=0x7f)
        card.cmd("no partial settings failure", 0xc0, status=0x6986)
        assert snapshot() == before
        # ClientPIN does not depend on the SM2 record. ADMIN must also remain
        # reachable to repair the actual damaged record, without credential reset.
        assert call(6, {1: 1, 2: 1})[3] == 8
        admin()
        card.cmd("verify to repair settings", 0x20, data=b"123456")
        if damage == "sm2-io":
            assert card.cmd("unchanged settings after read fault", 0x11) == custom
        else:
            card.cmd("reject malformed settings", 0x11, status=0x6900)
            card.cmd("repair settings", 0x12, data=custom)
        fido()
    assert call(4)[4]["clientPin"] is True
    expected_sm2 = -54 if damage == "missing-sm2" or unprovisioned else 2147483647
    assert call(4)[10][-1]["alg"] == expected_sm2
    signed = call(2, assertion)
    credential.public_key.verify(signed[2] + client_hash, signed[3])
    counter = AuthenticatorData(signed[2]).counter
    assert counter > AuthenticatorData(made[2]).counter
    # Discover the resident credential as well as opening its explicit handle.
    discovered = call(2, {1: "boot.example", 2: client_hash})
    assert discovered[1] == descriptor
    credential.public_key.verify(discovered[2] + client_hash, discovered[3])
    assert AuthenticatorData(discovered[2]).counter > counter
    assert call(12, {1: len(blob), 3: 0})[1] == blob
    public, secret = protocol.encapsulate(call(6, {1: 1, 2: 2})[1])
    pin_hash = protocol.encrypt(secret, hashlib.sha256(b"12345678").digest()[:16])
    token = protocol.decrypt(secret, call(6, {1: 1, 2: 5, 3: public, 6: pin_hash})[2])
    assert len(token) == 32 and any(token), "the original PIN must still authorize"
    if damage in ("missing-key", "short-key", "key-io"):
        call(1, registration | {7: {"rk": False}}, 0x7f)
        card.cmd("no fallback or partial registration", 0xc0, status=0x6986)
    if damage in ("missing-cert", "empty-cert") or unprovisioned:
        fresh = call(1, registration | {7: {"rk": False}})
        assert set(fresh[3]) == {"alg", "sig"}
        AuthenticatorData(fresh[2]).credential_data.public_key.verify(
            fresh[2] + client_hash, fresh[3]["sig"])
    # Repair through the public ADMIN path, which streams the certificate.
    admin()
    card.cmd("verify to restore manufacturing material", 0x20, data=b"123456")
    if unprovisioned:
        verify_attestation = provision(card)
    else:
        card.cmd("restore key", 1, data=saved_key)
        card.cmd("restore certificate", 2, data=saved_certificate)
    card.cmd("restore SM2", 0x12, data=custom)
    before = snapshot()
    wire.command("RESET")
    assert snapshot() == before
    fido()
    signed = call(2, assertion)
    credential.public_key.verify(signed[2] + client_hash, signed[3])
    assert AuthenticatorData(signed[2]).counter > counter
    verify_attestation(call(1, registration | {7: {"rk": False}}), client_hash)
    print(f"CTAP boot preservation {damage}: {len(card.checks)} checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    with connection(args.host) as wire:
        run(wire)
    for damage in BOOT_CASES:
        with connection(args.host) as wire:
            boot_preserves(wire, damage)
