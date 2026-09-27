# SPDX-License-Identifier: Apache-2.0
"""Independent public-key decoding for the OpenPGP and PIV suites."""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

CURVES = {0: ec.SECP256R1, 1: ec.SECP256K1, 2: ec.SECP384R1, 8: ec.SECP521R1}

from card_test import fields, tlv
from pathlib import Path
import json
import math


def pubkey(alg, wire):
    f = fields(wire)
    if alg in (5, 6, 7):
        assert len(f[0x81]) == (alg - 3) * 128
        assert len(f[0x82]) == 4
        assert wire == tlv(0x81, f[0x81]) + tlv(0x82, f[0x82])
    else:
        assert wire == tlv(0x86, f[0x86])
        if alg == 8:
            assert len(wire) == 136 and wire[:4] == bytes.fromhex("86818504")
    if alg in (5, 6, 7):
        return rsa.RSAPublicNumbers(
            int.from_bytes(f[0x82], "big"), int.from_bytes(f[0x81], "big")
        ).public_key()
    if alg in CURVES:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVES[alg](), f[0x86])
    return (ed25519.Ed25519PublicKey if alg == 3 else x25519.X25519PublicKey).from_public_bytes(
        f[0x86]
    )


ALICE_PRIVATE_LE = bytes.fromhex("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a")
ALICE_PUBLIC = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")


def encoding_vectors():
    vector = json.loads((Path(__file__).parent / "vectors/rsa4096-public.json").read_text())
    p, q = (int(vector[name], 16) for name in ("p", "q"))
    e = 65537
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    key = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                               rsa.RSAPublicNumbers(e, p * q)).private_key()
    # The old fixture included the outer value length, but not its 7F49 tag.
    yield 7, key, bytes.fromhex(vector["expected"])[3:]
    key = ec.derive_private_key(int("d30519bcae8d180dbfcc94fe0b8383dc310185b0be97b4365083ebceccd75759", 16), ec.SECP256R1())
    # The legacy fixture supplied unrelated public coordinates; this literal
    # is independently derived from its private scalar for actual APDU import.
    yield 0, key, bytes.fromhex("8641045097865a263e1f2b77e27df40502ce794a2ccedf45b913ae1be9f253c57112357fbcfae76a1bb1a1f71d1fc540b52bf1f6a3601b338a18c767d2f71ce3837405")
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    yield 3, key, bytes.fromhex("8620d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def chained_import(c, ins, p1, p2, body, chunk_size):
    for offset in range(0, len(body), chunk_size):
        last = offset + chunk_size >= len(body)
        c.raw("fixed_fragment_import", ins, p1, p2, body[offset:offset + chunk_size],
              cla=0 if last else 0x10)
