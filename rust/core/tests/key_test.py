# SPDX-License-Identifier: Apache-2.0
"""Independent public-key decoding for the OpenPGP and PIV suites."""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

CURVES = {0: ec.SECP256R1, 1: ec.SECP256K1, 2: ec.SECP384R1, 8: ec.SECP521R1}

from card_test import fields


def pubkey(alg, wire):
    f = fields(wire)
    if alg in (5, 6, 7):
        return rsa.RSAPublicNumbers(
            int.from_bytes(f[0x82], "big"), int.from_bytes(f[0x81], "big")
        ).public_key()
    if alg in CURVES:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVES[alg](), f[0x86])
    return (ed25519.Ed25519PublicKey if alg == 3 else x25519.X25519PublicKey).from_public_bytes(
        f[0x86]
    )
