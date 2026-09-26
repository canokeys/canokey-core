#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent host cryptographic verification of Rust PIV APDUs."""

import argparse
import datetime
import hashlib
import json

import piv_sm2 as sm2
from card_test import Card, connection, fields, tlv
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    utils,
    x25519,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from key_test import CURVES, pubkey, encoding_vectors, chained_import, ALICE_PRIVATE_LE, ALICE_PUBLIC

AID = bytes.fromhex("a000000308000010000100")
PIN = b"123456\xff\xff"
KEY = bytes(range(1, 9)) * 3
IDS = [0x11, 0x53, 0x14, 0xE0, 0xE1, 7, 5, 0x16, 0x15]


def aes(key, b, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(b) + ctx.finalize()


class Piv(Card):
    def select(self):
        return self.cmd("select_piv", 0xA4, 4, data=AID)

    def verify(self):
        return self.cmd("verify_pin", 0x20, 0, 0x80, PIN, le=None)

    def auth(self, key=KEY):
        encoded = self.cmd("witness", 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))
        witness = fields(fields(encoded)[0x7C])[0x80]
        assert len(witness) == 16 and encoded == tlv(0x7C, tlv(0x80, witness))
        challenge = bytes(range(16))
        reply = self.cmd(
            "prove_management",
            0x87,
            0x0A,
            0x9B,
            tlv(0x7C, tlv(0x80, aes(key, witness, True)) + tlv(0x81, challenge) + tlv(0x82, b"")),
        )
        assert reply == tlv(0x7C, tlv(0x82, aes(key, challenge)))

    def public(self, a, slot=0x9A):
        return pubkey(a, fields(self.cmd(f"metadata_alg_{a}", 0xF7, 0, slot))[4])

    def generate(self, a, slot=0x9A, policies=b""):
        reply = self.cmd(
            f"generate_alg_{a}", 0x47, 0, slot, tlv(0xAC, tlv(0x80, bytes([IDS[a]])) + policies)
        )
        value = fields(reply)[0x7f49]
        assert reply == tlv(0x7f49, value)
        return pubkey(a, value)

    def import_key(self, a, key, slot=0x9A):
        if a in (5, 6, 7):
            k = key.private_numbers()
            w = key.key_size // 16
            body = b"".join(
                tlv(i + 1, v.to_bytes(w, "big"))
                for i, v in enumerate([k.p, k.q, k.dmp1, k.dmq1, k.iqmp])
            )
        else:
            scalar = (
                key.private_numbers().private_value.to_bytes((key.curve.key_size + 7) // 8, "big")
                if a in CURVES
                else key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
            body = tlv(6, scalar)
        self.cmd("import", 0xFE, IDS[a], slot, body, le=None)

    def ga(self, a, slot, data, tag=0x81, status=0x9000):
        result = self.cmd(
            "private_op",
            0x87,
            IDS[a],
            slot,
            tlv(0x7C, tlv(0x82, b"") + tlv(tag, data)),
            status=status,
        )
        return fields(fields(result)[0x7C])[0x82] if status == 0x9000 else None

    def get(self, tag, status=0x9000):
        value = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
        return self.cmd("get_object", 0xCB, 0x3F, 0xFF, tlv(0x5C, value), status=status)

    def put(self, tag, value):
        t = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
        self.cmd("put_object", 0xDB, 0x3F, 0xFF, tlv(0x5C, t) + value, le=None)


def exercise(c, a, key):
    c.verify()
    if a == 4:
        peer = x25519.X25519PrivateKey.generate()
        point = peer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        assert c.ga(a, 0x9A, point, 0x85) == peer.exchange(key)
    elif a in (5, 6, 7):
        n = key.key_size // 8
        value = (42).to_bytes(n, "big")
        sig = c.ga(a, 0x9A, value)
        assert pow(int.from_bytes(sig, "big"), key.public_numbers().e, key.public_numbers().n) == 42
    else:
        msg = b"Independent PIV verification"
        value = hashlib.sha256(msg).digest() if a in CURVES else msg
        sig = c.ga(a, 0x9A, value)
        if a in CURVES:
            key.verify(sig, value, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        else:
            key.verify(sig, msg)
        if a in CURVES:
            peer = ec.generate_private_key(CURVES[a]())
            point = peer.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            assert c.ga(a, 0x9A, point, 0x85) == peer.exchange(ec.ECDH(), key)


def authentication(c):
    c.select()
    c.cmd("pin_status", 0x20, 0, 0x80, le=None, status=0x63C3)
    assert c.get(0x7E)[:2] == b"\x7e\x12"
    assert len(c.get(0x5FC107)) == 53 and len(c.get(0x5FC102)) == 61
    c.cmd("unauthorized_generate", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\x11")), status=0x6982)
    challenge = fields(
        fields(c.cmd("external_challenge", 0x87, 0, 0x9B, tlv(0x7C, tlv(0x81, b""))))[0x7C]
    )[0x81]
    proof = tlv(0x7C, tlv(0x82, aes(KEY, challenge)))
    c.cmd("external_authenticate", 0x87, 0, 0x9B, proof, le=None)
    c.cmd("external_replay_rejected", 0x87, 0, 0x9B, proof, status=0x6982)
    c.auth()
    c.verify()
    c.select()
    c.cmd("reselect_preserves_pin", 0x20, 0, 0x80, le=None)


def host_managed_objects(c):
    printed = bytes.fromhex("531c881a8918") + KEY
    admin = bytes.fromhex("53058003810103")
    management_size = c.wire.command("SIZE 15")
    c.put(0x5FC109, printed)
    c.put(0x5FFF00, admin)
    assert c.wire.command("SIZE 15") == management_size
    c.wire.command("RESET")
    c.select()
    assert c.get(0x5FFF00) == admin
    c.get(0x5FC109, status=0x6982)
    put = bytes.fromhex("5c035fc1055301aa")
    for verified in (False, True):
        if verified:
            c.verify()
        c.cmd("pin_does_not_grant_management", 0xDB, 0x3F, 0xFF, put, status=0x6982)
        c.get(0x5FC105, status=0x6A82)
        assert c.wire.command("SIZE 42") == b"\xff" * 4
    assert c.get(0x5FC109) == printed
    assert c.raw("bounded_printed_read", 0xCB, 0x3F, 0xFF,
                 bytes.fromhex("5c035fc109"), le=256) == printed
    # Host-managed printed/admin objects never replace the AES management key.
    c.auth()
    c.put(0x5FC105, bytes.fromhex("5301aa"))
    assert c.wire.command("SIZE 42") == (3).to_bytes(4, "big")
    c.put(0x5FC105, bytes.fromhex("5300"))
    c.get(0x5FC105, status=0x6A82)
    assert c.wire.command("SIZE 42") == b"\xff" * 4


def management_rotation(c):
    metadata = c.cmd("management_default_metadata", 0xF7, 0, 0x9B)
    assert metadata == bytes.fromhex("01010a02020001050101")
    c.cmd("signature_key_absent", 0xF7, 0, 0x9C, status=0x6A88)
    new_key = bytes.fromhex("101112131415161720212223242526273031323334353637")
    body = bytes.fromhex("0a9b18") + new_key
    c.cmd("management_touch_required", 0xFF, 0xFF, 0xFE, body, le=None)
    assert c.cmd("management_touch_metadata", 0xF7, 0, 0x9B) == bytes.fromhex("01010a02020002050100")
    c.cmd("management_invalid_touch_selector", 0xFF, 0xFF, 0xFD, body, status=0x6A86)
    c.cmd("management_touch_disabled", 0xFF, 0xFF, 0xFF, body, le=None)
    assert c.cmd("management_rotated_metadata", 0xF7, 0, 0x9B) == bytes.fromhex("01010a02020001050100")
    c.wire.command("RESET")
    c.select()
    c.auth(new_key)
    for algorithm in (3, 8, 0x0C):
        c.cmd("unsupported_management_algorithm", 0x87, algorithm, 0x9B,
              tlv(0x7C, tlv(0x81, b"")), status=0x6A86)
    c.auth(new_key)
    c.cmd("restore_management", 0xFF, 0xFF, 0xFF, bytes.fromhex("0a9b18") + KEY, le=None)
    c.auth()
    c.verify()


def object_capacity(c):
    for tag, record in [(0x5FC10D, 46), (0x5FC10E, 47), (0x5FC10F, 48), (0x5FC120, 65)]:
        assert c.wire.command(f"SIZE {record}") == b"\xff" * 4
        c.put(tag, bytes.fromhex("530155"))
        assert c.wire.command(f"SIZE {record}") == (3).to_bytes(4, "big")
        assert c.get(tag) == bytes.fromhex("530155")
        c.put(tag, b"\x53\x00")
    certificate = tlv(0x53, bytes(i % 256 for i in range(6564)))
    c.put(0x5FC105, certificate)
    assert len(certificate) == 6568 and c.get(0x5FC105) == certificate
    c.cmd("certificate_over_capacity", 0xDB, 0x3F, 0xFF,
          bytes.fromhex("5c035fc105") + certificate + b"\0", status=0x6700)
    assert c.get(0x5FC105) == certificate
    c.put(0x5FC105, b"\x53\x00")
    tags = [0x5FC102, 0x5FC103, 0x5FC106, 0x5FC107, 0x5FC108, 0x5FC109, 0x5FC10C, 0x5FC121]
    value = tlv(0x53, bytes(i % 256 for i in range(3036)))
    assert len(value) == 3040
    for tag, record in zip(tags, range(67, 75)):
        c.put(tag, value)
        assert c.get(tag) == value
        assert c.wire.command(f"SIZE {record}") == (3040).to_bytes(4, "big")
    c.cmd("data_object_over_capacity", 0xDB, 0x3F, 0xFF,
          bytes.fromhex("5c035fc106") + value + b"\0", status=0x6700)
    assert c.get(0x5FC106) == value
    for tag in (0x5FC109, 0x5FC121):
        c.raw("small_first_object_fragment", 0xDB, 0x3F, 0xFF,
              tlv(0x5C, tag.to_bytes(3, "big")) + bytes.fromhex("5303aa"), cla=0x10)
        c.raw("last_object_fragment", 0xDB, 0x3F, 0xFF, bytes.fromhex("bbcc"))
        assert c.get(tag) == bytes.fromhex("5303aabbcc")
    for size in (64, 80, 30):
        value = bytes(range(5, 5 + size))
        c.put(0x5FC109, value)
        assert c.get(0x5FC109) == value
        assert c.wire.command("SIZE 72") == size.to_bytes(4, "big")
    value = bytes((0x85 + i) % 256 for i in range(128))
    c.put(0x5FFF00, value)
    c.cmd("admin_object_over_capacity", 0xDB, 0x3F, 0xFF,
          bytes.fromhex("5c035fff00") + bytes(129), status=0x6700)
    assert c.get(0x5FFF00) == value
    for tag, value in [(0x5FC106, bytes.fromhex("53021122")), (0x5FC10C, bytes.fromhex("530133"))]:
        c.put(tag, value)
        assert c.get(tag) == value


def objects(c):
    for tag in [0x5FC105, 0x5FC10D, 0x5FC120, 0x5FC109, 0x5FFF00]:
        value = tlv(0x53, bytes(i % 256 for i in range(120 if tag == 0x5FFF00 else 2700)))
        c.put(tag, value)
        assert c.get(tag) == value
    c.put(0x5FC105, b"\x53\x00")
    c.get(0x5FC105, status=0x6A82)


def classic_keys(c):
    for a in range(9):
        public = c.generate(a)
        exercise(c, a, public)
        key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048 + (a - 5) * 1024)
            if a in (5, 6, 7)
            else (
                ec.generate_private_key(CURVES[a]())
                if a in CURVES
                else (ed25519.Ed25519PrivateKey if a == 3 else x25519.X25519PrivateKey).generate()
            )
        )
        c.import_key(a, key)
        exercise(c, a, c.public(a))
        assert c.public(a).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def import_boundary_regressions(c):
    private = ec.generate_private_key(ec.SECP256R1())
    c.import_key(0, private)
    before = c.cmd("import_baseline", 0xf7, 0, 0x9a)
    for algorithm in (0x08, 0x0c, 0xff):
        c.cmd("invalid_public_algorithm", 0x47, 0, 0x9a,
              tlv(0xac, tlv(0x80, bytes([algorithm]))), status=0x6a80)
        assert c.cmd("failed_generate_keeps_key", 0xf7, 0, 0x9a) == before
    c.cmd("empty_rsa_component", 0xfe, 0x16, 0x9a, bytes.fromhex("0100a5"), status=0x6a80)
    c.cmd("oversized_rsa_component", 0xfe, 0x16, 0x9a, bytes.fromhex("01820101a5"), status=0x6a80)
    c.cmd("completed_rsa_component", 0xfe, 0x16, 0x9a, bytes.fromhex("0101a5a5"), status=0x6a80)
    scalar = private.private_numbers().private_value.to_bytes(32, "big")
    for tail in (b"\xaa", b"\xaa\x01", b"\xab", b"\xab\x01"):
        c.cmd("truncated_generation_policy", 0x47, 0, 0x9a,
              tlv(0xac, tlv(0x80, b"\x11") + tail), status=0x6700)
        c.cmd("truncated_import_policy", 0xfe, 0x11, 0x9a,
              tlv(6, scalar) + tail, status=0x6700)
        assert c.cmd("failed_import_keeps_policy_and_key", 0xf7, 0, 0x9a) == before
    exercise(c, 0, private.public_key())


def encoding_regressions(c):
    for algorithm, private, expected in encoding_vectors():
        c.import_key(algorithm, private)
        assert fields(c.cmd("fixed_public_encoding", 0xf7, 0, 0x9a))[4] == expected
        exercise(c, algorithm, private.public_key())
    chained_import(c, 0xfe, IDS[4], 0x9a, tlv(8, ALICE_PRIVATE_LE), 5)
    assert fields(c.cmd("alice_public_encoding", 0xf7, 0, 0x9a))[4] == bytes.fromhex("8620") + ALICE_PUBLIC
    exercise(c, 4, x25519.X25519PrivateKey.from_private_bytes(ALICE_PRIVATE_LE).public_key())
    for seed in (bytes(32), bytes([255]) * 32, bytes(i * 2 + 1 for i in range(32)), bytes(i * 3 + 1 for i in range(32))):
        c.cmd("mldsa_fixed_seed", 0xfe, 0xe2, 0x9a, tlv(9, seed))
        public = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
        expected = bytes.fromhex("868207a0") + public
        assert len(public) == 1952
        for _ in range(2):
            assert fields(c.cmd("mldsa_fixed_encoding", 0xf7, 0, 0x9a))[4] == expected


def pq_keys(c):
    for alg, cls, size, seed_tag in [
        (0xE2, mldsa.MLDSA65PublicKey, 32, 9),
        (0xE3, mlkem.MLKEM768PublicKey, 64, 10),
    ]:
        for imported in [False, True]:
            if imported:
                c.cmd("pq_import", 0xFE, alg, 0x9A, tlv(seed_tag, bytes(range(size))), le=None)
                encoded = fields(c.cmd("pq_metadata", 0xF7, 0, 0x9A))[4]
            else:
                encoded = fields(
                    c.cmd(
                        f"pq_generate_{alg:02x}", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, bytes([alg])))
                    )
                )[0x7F49]
            public = cls.from_public_bytes(fields(encoded)[0x86])
            c.verify()
            if imported:
                private = (
                    mldsa.MLDSA65PrivateKey if alg == 0xE2 else mlkem.MLKEM768PrivateKey
                ).from_seed_bytes(bytes(range(size)))
                assert private.public_key().public_bytes_raw() == public.public_bytes_raw()
            if alg == 0xE2:
                for message in [b"", bytes(range(256)) * 20]:
                    answer = c.cmd(
                        "pq_sign", 0x87, alg, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, message))
                    )
                    public.verify(fields(fields(answer)[0x7C])[0x82], message)
            else:
                shared, ciphertext = public.encapsulate()
                answer = c.cmd(
                    "pq_decaps", 0x87, alg, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, ciphertext))
                )
                assert fields(fields(answer)[0x7C])[0x82] == shared
                changed = bytearray(ciphertext)
                changed[42] ^= 1
                expected = private.decapsulate(bytes(changed)) if imported else None
                results = []
                for _ in range(2):
                    answer = c.cmd(
                        "pq_implicit_rejection",
                        0x87,
                        alg,
                        0x9A,
                        tlv(0x7C, tlv(0x82, b"") + tlv(0x81, bytes(changed))),
                    )
                    results.append(fields(fields(answer)[0x7C])[0x82])
                assert (
                    results[0] == results[1]
                    and results[0] != shared
                    and (expected is None or results[0] == expected)
                )


def randomized_ed25519(c):
    key = c.generate(3)
    c.verify()
    message = bytes(range(256)) * 20
    signatures = []
    for _ in range(2):
        result = c.cmd(
            "randomized_ed25519", 0x87, 0xFF, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, message))
        )
        sig = fields(fields(result)[0x7C])[0x82]
        key.verify(sig, message)
        signatures.append(sig)
    assert signatures[0] != signatures[1]


def sm2_operations(c):
    c.cmd("sm2_import", 0xFE, 0x54, 0x9A, tlv(6, sm2.V_DA), le=None)
    c.verify()
    public = fields(fields(c.cmd("sm2_metadata", 0xF7, 0, 0x9A))[4])[0x86][1:]
    assert public == sm2.V_PA

    def verify_sm2(sig, digest):
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        assert 0 < r < sm2.N and 0 < s < sm2.N
        point = sm2.point_add(
            sm2.point_mul(s, sm2.G),
            sm2.point_mul((r + s) % sm2.N, (sm2.b2i(public[:32]), sm2.b2i(public[32:]))),
        )
        assert point is not None and (int.from_bytes(digest, "big") + point[0]) % sm2.N == r

    digest = bytes(range(32))
    reply = c.cmd(
        "sm2_digest_sign", 0x87, 0x54, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest))
    )
    verify_sm2(fields(fields(reply)[0x7C])[0x82], digest)
    for own in [None, b"custom SM2 identity"]:
        message = bytes(range(256)) * 20
        reply = c.cmd(
            "sm2_stream_sign",
            0x87,
            0x54,
            0x9A,
            tlv(0x7C, (tlv(0x80, own) if own else b"") + tlv(0x82, b"") + tlv(0x81, message)),
        )
        verify_sm2(
            fields(fields(reply)[0x7C])[0x82],
            sm2.sm3(sm2.sm2_z(own or sm2.ID_DEFAULT, public) + message),
        )
    exp = tlv(0x86, b"\x04" + sm2.V_PB) + tlv(0x87, b"\x04" + sm2.V_EB)
    reply = c.cmd("sm2_initiator_start", 0x87, 0x54, 0x9A, tlv(0x7C, tlv(0x82, b"")))
    eph = fields(fields(reply)[0x7C])[0x82][1:]
    expected = sm2.key_exchange_full(
        1, sm2.ID_DEFAULT, sm2.ID_DEFAULT, sm2.V_DB, sm2.V_PB, sm2.V_RB, sm2.V_EB, public, eph, 16
    )[0]
    reply = c.cmd(
        "sm2_initiator_finish", 0x87, 0x54, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x85, exp))
    )
    assert fields(fields(reply)[0x7C])[0x82] == expected
    reply = c.cmd("sm2_responder", 0x87, 0x54, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x85, exp)))
    values = fields(fields(reply)[0x7C])
    expected = sm2.key_exchange_full(
        0,
        sm2.ID_DEFAULT,
        sm2.ID_DEFAULT,
        sm2.V_DB,
        sm2.V_PB,
        sm2.V_RB,
        sm2.V_EB,
        public,
        values[0x82][1:],
        16,
    )[0]
    assert values[0x85] == expected
    c.cmd(
        "sm2_reject_plain_ecdh",
        0x87,
        0x54,
        0x9A,
        tlv(0x7C, tlv(0x82, b"") + tlv(0x85, b"\x04" + sm2.V_PB)),
        status=0x6A80,
    )


def attestation(c):
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    c.import_key(0, issuer_key, 0xF9)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Independent attestation CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(issuer_key.public_key())
        .serial_number(17)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(issuer_key, hashes.SHA256())
    )
    c.put(
        0x5FFF01,
        tlv(
            0x53,
            tlv(0x70, issuer.public_bytes(serialization.Encoding.DER))
            + tlv(0x71, b"\0")
            + tlv(0xFE, b""),
        ),
    )
    for alg in list(range(9)) + [11]:
        if alg == 11:
            encoded = fields(
                c.cmd("attest_pq_generate", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\xe2")))
            )[0x7F49]
            public = mldsa.MLDSA65PublicKey.from_public_bytes(fields(encoded)[0x86])
        else:
            public = c.generate(alg)
        certificate = x509.load_der_x509_certificate(c.cmd(f"attest_alg_{alg}", 0xF9, 0x9A))
        issuer_key.public_key().verify(
            certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
        )
        assert certificate.issuer == issuer.subject
        assert certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    c.import_key(0, issuer_key)
    c.cmd("no_attestation_for_import", 0xF9, 0x9A, status=0x6A88)
    return issuer_key, issuer


def interruptions(c):
    raw = c.raw
    old = c.get(0x5FC109)
    raw(
        "put_interrupted",
        0xDB,
        0x3F,
        0xFF,
        tlv(0x5C, b"\x5f\xc1\x09") + b"new partial value",
        cla=0x10,
    )
    c.select()
    c.verify()
    assert c.get(0x5FC109) == old
    before = c.public(0).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    raw("import_interrupted", 0xFE, 0x11, 0x9A, b"\x06\x20" + b"\1" * 8, cla=0x10)
    c.select()
    assert (
        c.public(0).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == before
    )
    c.cmd("malformed_get", 0xCB, 0x3F, 0xFF, b"\x5c\x03\x5f", status=0x6700)
    c.cmd("read_only_discovery", 0xDB, 0x3F, 0xFF, tlv(0x5C, b"\x7e") + b"bad", status=0x6A82)
    raw("name_chaining_forbidden", 0xF5, 1, 0x9A, b"ab", cla=0x10, status=0x6E00)
    c.cmd("invalid_utf16", 0xF5, 1, 0x9A, b"\x00\xd8", status=0x6A80)
    public = c.generate(3)
    c.verify()
    message = b"x" * 544
    public.verify(c.ga(3, 0x9A, message), message)
    raw(
        "oversized_deterministic_ed25519",
        0x87,
        0xE0,
        0x9A,
        tlv(0x7C, tlv(0x82, b"") + tlv(0x81, b"x" * 545))[:80],
        cla=0x10,
        status=0x6700,
    )
    raw("pq_partial_public", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\xe2")), le=1, status=0x61FF)
    c.select()
    raw("abandoned_public_not_readable", 0xC0, le=256, status=0x6986)
    c.verify()
    body = tlv(0x7C, tlv(0x82, b"") + tlv(0x81, b"x" * 1000))
    raw("pq_partial_sign", 0x87, 0xE2, 0x9A, body[:80], cla=0x10)
    c.select()
    c.wire.command("RESET")
    c.select()
    c.auth()
    c.verify()
    reply = c.cmd(
        "pq_after_abort", 0x87, 0xE2, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, b"abort recovery"))
    )
    public = mldsa.MLDSA65PublicKey.from_public_bytes(
        fields(fields(c.cmd("pq_after_abort_public", 0xF7, 0, 0x9A))[4])[0x86]
    )
    public.verify(fields(fields(reply)[0x7C])[0x82], b"abort recovery")


def slots(c):
    for slot in range(0x82, 0x96):
        c.generate(0, slot)
    directory = fields(c.cmd("directory", 0xF7, 1, 0))
    entries = directory[2]
    assert all(slot in entries[::6] for slot in range(0x82, 0x96))
    for slot in range(0x82, 0x96):
        c.cmd("delete_retired", 0xF6, 0xFF, slot, le=None)
    c.generate(0)
    c.verify()
    name = "PIV测试".encode("utf-16le")
    c.cmd("name_set", 0xF5, 1, 0x9A, name, le=None)
    assert c.cmd("name_get", 0xF5, 0, 0x9A) == name
    c.cmd("move", 0xF6, 0x82, 0x9A, le=None)
    assert c.cmd("moved_name", 0xF5, 0, 0x82) == name
    c.cmd("absent_metadata", 0xF7, 0, 0x9A, status=0x6A88)
    c.cmd("delete", 0xF6, 0xFF, 0x82, le=None)
    c.generate(0, 0x9C)
    c.verify()
    digest = hashlib.sha256(b"once").digest()
    c.ga(0, 0x9C, digest)
    c.cmd("query_does_not_reauthorize_always_pin", 0x20, 0, 0x80, le=None)
    c.ga(0, 0x9C, digest, status=0x6982)


def reset_and_persistence(c, issuer_key, issuer):
    c.cmd("set_retries", 0xFA, 5, 4, le=None)
    assert fields(c.cmd("pin_metadata", 0xF7, 0, 0x80))[6] == b"\x05\x05"
    c.cmd("unauthorized_after_retries", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\x11")), status=0x6982)
    c.auth()
    new = bytes(range(24))
    c.cmd("rotate_management", 0xFF, 0xFF, 0xFF, bytes([0x0A, 0x9B, 24]) + new, le=None)
    c.auth(new)
    original_config = c.cmd("read_algorithms", 0xEE, 1, 0)
    config = bytearray(original_config)
    config[1] = 0xE4
    c.cmd("write_algorithms", 0xEE, 2, 0, bytes(config), le=None)
    c.wire.command("RESET")
    c.select()
    assert c.cmd("persistent_algorithms", 0xEE, 1, 0) == bytes(config)
    c.cmd("reset_clears_pin", 0x20, 0, 0x80, le=None, status=0x63C5)
    c.auth(new)
    for i in range(5):
        c.cmd(
            "block_pin", 0x20, 0, 0x80, b"00000000", le=None, status=0x63C4 - i if i < 4 else 0x6983
        )
    for i in range(4):
        c.cmd(
            "block_puk",
            0x24,
            0,
            0x81,
            b"0000000012345678",
            le=None,
            status=0x63C3 - i if i < 3 else 0x6983,
        )
    c.cmd("factory_reset", 0xFB, le=None)
    c.auth()
    c.verify()
    c.cmd("reset_deleted_key", 0xF7, 0, 0x9C, status=0x6A88)
    assert c.get(0x5FFF01) == tlv(
        0x53,
        tlv(0x70, issuer.public_bytes(serialization.Encoding.DER))
        + tlv(0x71, b"\0")
        + tlv(0xFE, b""),
    )
    assert c.cmd("reset_preserved_algorithms", 0xEE, 1, 0) == bytes(config)
    assert c.public(0, 0xF9).public_numbers() == issuer_key.public_key().public_numbers()
    c.cmd("restore_algorithms", 0xEE, 2, 0, original_config, le=None)


def run(wire, progress=None, report=None):
    c = Piv(wire, progress, report)
    try:
        for scenario in (
            authentication,
            host_managed_objects,
            management_rotation,
            object_capacity,
            objects,
            classic_keys,
            encoding_regressions,
            import_boundary_regressions,
            pq_keys,
            randomized_ed25519,
            sm2_operations,
        ):
            c.report["scenario"] = scenario.__name__
            scenario(c)
        c.report["scenario"] = "attestation"
        issuer_key, issuer = attestation(c)
        for scenario in (interruptions, slots):
            c.report["scenario"] = scenario.__name__
            scenario(c)
        c.report["scenario"] = "reset_and_persistence"
        reset_and_persistence(c, issuer_key, issuer)
    except Exception as error:
        c.report["error"] = repr(error)
        raise
    c.report["passed"] = True
    return c.report


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("--host", required=True)
    a = args.parse_args()
    with connection(a.host) as wire:
        print(json.dumps(run(wire)))
