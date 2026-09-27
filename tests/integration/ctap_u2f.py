#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CTAP1 polling, packed registration and independently verified assertions."""
import argparse
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from card_test import Card, connection
from ctap_fixture import provision


def run(wire):
    card = Card(wire)
    provision(card)
    assert card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001")) == b"U2F_V2"
    # U2F is P-256-only: unrelated SM2 provisioning must not gate its commands.
    sm2_record = wire.command("RECORD 181")
    assert sm2_record[-2:] == b"\x90\x00"
    wire.command("RECORD 181 00")
    # Unknown U2F commands must report INS, including case-2 extended APDUs.
    for ins in (0, 4, 0xff):
        for suffix in (b"\x00", b"\x00\x00\x00", b"\x00\x00\x01x\x00\x00"):
            assert wire.transmit(bytes([0, ins, 0, 0]) + suffix) == (b"", 0x6d, 0)
    assert card.cmd("version", 3) == b"U2F_V2"
    card.cmd("version length", 3, data=b"x", status=0x6700)
    challenge = hashlib.sha256(b"challenge").digest()
    app = hashlib.sha256(b"example.com").digest()
    card.cmd("register length", 1, data=challenge, status=0x6700)
    card.cmd("registration polls", 1, data=challenge + app, status=0x6985)
    wire.command("POLL 100")
    result = card.cmd("register", 1, data=challenge + app)
    assert result[:2] == b"\x05\x04"
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), result[1:66])
    n = result[66]
    handle = result[67:67+n]
    tail = result[67+n:]
    # DER certificate is followed by the registration signature.
    width = tail[1] & 127
    cert_len = 2 + width + int.from_bytes(tail[2:2+width], "big") if tail[1] & 128 else 2 + tail[1]
    cert = x509.load_der_x509_certificate(tail[:cert_len])
    cert.public_key().verify(tail[cert_len:], b"\x00" + app + challenge + handle + result[1:66], ec.ECDSA(hashes.SHA256()))
    wire.command(f"RECORD 181 {sm2_record[:-2].hex()}")
    request = challenge + app + bytes([n]) + handle
    for algorithm in (1, 2, 3, 255):
        other = request[:65] + bytes([algorithm]) + handle[1:]
        card.cmd("reject non-P256 handle", 2, 7, data=other, status=0x6a80)
    # Policy is read on each command, even when VERSION was just served.
    policy = bytes(16) + bytes([8, 0, 4, 1])
    wire.command(f"RECORD 77 {policy.hex()}")
    assert card.cmd("version with alwaysUv", 3) == b"U2F_V2"
    card.cmd("alwaysUv blocks registration", 1, data=challenge+app, status=0x6d00)
    card.cmd("alwaysUv blocks authentication", 2, 7, data=request, status=0x6d00)
    wire.command("RECORD 77 00")
    card.cmd("malformed policy fails closed", 2, 7, data=request, status=0x6900)
    wire.command("REMOVE 77")
    card.cmd("authenticate length", 2, 3, data=request[:-1], status=0x6a80)
    card.cmd("handle length", 2, 3, data=request[:64] + bytes([n-1]) + handle, status=0x6700)
    invalid = request[:-1] + bytes([request[-1] ^ 1])
    card.cmd("invalid check only", 2, 7, data=invalid, status=0x6a80)
    card.cmd("check only", 2, 7, data=request, status=0x6985)
    card.cmd("gesture consumed", 2, 3, data=request, status=0x6985)
    wire.command("POLL 100")
    card.cmd("check only preserves gesture", 2, 7, data=request, status=0x6985)
    previous = 0
    wire.command("RECORD 181 00")
    for p1 in (3, 8): # The C implementation requires presence for both values.
        if p1 == 8:
            wire.command(f"RECORD 181 {sm2_record[:-2].hex()}")
            # Reinstall must preserve the credential and monotonic signing counter,
            # while volatile presence is cleared by a real session reset.
            wire.command("RESET")
            card.cmd("fido after reset", 0xa4, 4, data=bytes.fromhex("a0000006472f0001"))
            card.cmd("p1=8 still polls", 2, p1, data=request, status=0x6985)
            wire.command("POLL 100")
        response = card.cmd("authenticate", 2, p1, data=request)
        assert response[0] == 1
        counter = int.from_bytes(response[1:5], "big")
        assert counter > previous
        previous = counter
        public.verify(response[5:], app + response[:5] + challenge, ec.ECDSA(hashes.SHA256()))
    # ADMIN reset removes U2F credentials, while the device certificate survives.
    card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    card.cmd("verify", 0x20, data=b"123456")
    card.cmd("reset ctap", 9)
    assert card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001")) == b"U2F_V2"
    card.cmd("erased handle", 2, 7, data=request, status=0x6a80)
    wire.command("POLL 100")
    assert card.cmd("reprovision unnecessary", 1, data=challenge + app)[0] == 5
    card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    card.cmd("verify", 0x20, data=b"123456")
    card.cmd("empty certificate", 2, data=b"")
    assert card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001")) == b"U2F_V2"
    wire.command("POLL 100")
    assert card.cmd("empty certificate rejects registration", 1, data=challenge+app, status=0x6900) == b""
    card.cmd("no partial empty-certificate registration", 0xc0, status=0x6986)
    provision(card)
    assert card.cmd("fido", 0xa4, 4, data=bytes.fromhex("a0000006472f0001")) == b"U2F_V2"
    wire.command("REMOVE 182") # CtapAttestationKey; certificate remains provisioned.
    wire.command("POLL 100")
    assert card.cmd("missing attestation key", 1, data=challenge+app, status=0x6900) == b""
    card.cmd("no partial registration response", 0xc0, status=0x6986)
    print(f"CTAP1: {len(card.checks)} checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    with connection(args.host) as wire:
        run(wire)
