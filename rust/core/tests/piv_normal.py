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
        if a == 8:
            assert len(reply) == 140 and reply[:8] == bytes.fromhex("7f49818886818504")
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


def read_in_chunks(c, ins, p1, p2, data, expected):
    result = b""
    while len(result) < len(expected):
        length = min(256, len(expected) - len(result))
        remaining = len(expected) - len(result) - length
        status = 0x9000 if remaining == 0 else 0x6100 + min(remaining, 255)
        part = c.raw("bounded_response_chunk", ins, p1, p2, data, le=256, status=status)
        assert len(part) == length
        result += part
        ins, p1, p2, data = 0xC0, 0, 0, b""
    assert result == expected
    c.raw("completed_response_unavailable", 0xC0, le=256, status=0x6986)


def unauthenticated_queries(c):
    c.select()
    c.cmd("queries_without_pin", 0x20, 0, 0x80, le=None, status=0x63C3)
    version = c.raw("version_full", 0xFD, le=256)
    assert len(version) == 3
    assert c.raw("version_without_le", 0xFD) == version
    first = c.raw("version_first_byte", 0xFD, le=1, status=0x6102)
    last = c.raw("version_remaining", 0xC0, le=256)
    assert len(first) == 1 and first + last == version
    c.raw("version_no_more_data", 0xC0, le=256, status=0x6986)
    for length in (256, 32):
        assert len(c.raw("unauthenticated_random", 0x84, le=length)) == length
    c.raw("random_invalid_p1", 0x84, 1, le=32, status=0x6A86)
    c.raw("random_with_data", 0x84, data=b"x", le=32, status=0x6700)
    assert len(c.raw("random_without_le", 0x84)) == 256
    answer, a, b = c.wire.transmit(bytes.fromhex("00840000000101"))
    assert not answer and (a, b) == (0x67, 0)
    c.cmd("queries_do_not_grant_pin", 0x20, 0, 0x80, le=None, status=0x63C3)


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


def algorithm_configuration(c):
    c.wire.command("RESET")
    c.select()
    expected = bytes.fromhex("01e00516e1531554e2e3")
    assert c.cmd("public_algorithm_configuration", 0xEE, 1, 0) == expected
    c.cmd("unauthorized_algorithm_write", 0xEE, 2, 0, expected, le=None, status=0x6982)
    c.auth()
    c.cmd("write_default_algorithms", 0xEE, 2, 0, expected, le=None)
    for index, value in ((9, 0xE2), (1, 0xFF), (1, 0x11)):
        invalid = bytearray(expected)
        invalid[index] = value
        c.cmd("reject_conflicting_algorithm", 0xEE, 2, 0, bytes(invalid),
              le=None, status=0x6A80)
        assert c.cmd("failed_write_preserves_algorithms", 0xEE, 1, 0) == expected
    c.wire.command("RESET")
    c.select()
    assert c.cmd("public_algorithms_after_write", 0xEE, 1, 0) == expected
    c.cmd("reset_revokes_algorithm_write", 0xEE, 2, 0, expected, le=None, status=0x6982)
    c.auth()
    c.verify()


def retry_configuration(c):
    c.wire.command("RESET")
    c.select()
    c.auth()
    c.cmd("retry_limits_need_pin", 0xFA, 4, 5, status=0x6982)
    c.verify()
    for pin, puk in ((0, 5), (4, 16)):
        c.cmd("invalid_retry_limits", 0xFA, pin, puk, status=0x6A86)
    c.cmd("retry_limits_reject_data", 0xFA, 4, 5, b"x", status=0x6700)
    c.cmd("set_distinct_retry_limits", 0xFA, 4, 5)
    for reference, limit in ((0x80, 4), (0x81, 5)):
        metadata = fields(c.cmd("retry_limit_metadata", 0xF7, 0, reference))
        assert metadata[5] == b"\x01" and metadata[6] == bytes([limit, limit])
    c.cmd("retry_limits_revoke_pin", 0x20, 0, 0x80, status=0x63C4)
    c.cmd("retry_wrong_pin_charged", 0x20, 0, 0x80, b"000000\xff\xff", status=0x63C3)
    c.verify()
    c.cmd("retry_limits_need_management", 0xFA, 4, 5, status=0x6982)
    c.auth()
    c.wire.command("FAIL_WRITE 14")
    c.cmd("retry_limit_commit_failure", 0xFA, 6, 7, status=0x6900)
    c.cmd("failed_retry_write_revokes_management", 0xFA, 6, 7, status=0x6982)
    c.auth()
    c.cmd("failed_retry_write_revokes_pin", 0xFA, 6, 7, status=0x6982)
    c.cmd("failed_retry_cache_unavailable", 0x20, 0, 0x80, PIN, status=0x6900)
    c.wire.command("RESET")
    c.select()
    for reference, limit in ((0x80, 4), (0x81, 5)):
        assert fields(c.cmd("failed_retry_write_preserves_limits", 0xF7, 0, reference))[6] == bytes([limit, limit])
    c.auth()
    c.verify()
    c.cmd("maximum_retry_limits", 0xFA, 15, 15)
    assert fields(c.cmd("maximum_retry_metadata", 0xF7, 0, 0x80))[6] == b"\x0f\x0f"
    c.auth()
    c.verify()
    c.cmd("restore_retry_limits", 0xFA, 3, 3)
    c.auth()
    c.verify()


def object_capacity(c):
    for tag, record in [(0x5FC10D, 46), (0x5FC10E, 47), (0x5FC10F, 48), (0x5FC120, 65)]:
        assert c.wire.command(f"SIZE {record}") == b"\xff" * 4
        c.put(tag, bytes.fromhex("530155"))
        assert c.wire.command(f"SIZE {record}") == (3).to_bytes(4, "big")
        assert c.get(tag) == bytes.fromhex("530155")
        c.put(tag, b"\x53\x00")
    certificate = tlv(0x53, bytes(0xC0 + (i & 0x3F) for i in range(6564)))
    c.raw("certificate_first_put", 0xDB, 0x3F, 0xFF,
          bytes.fromhex("5c035fc105") + certificate[:204], cla=0x10)
    for offset in range(204, len(certificate), 200):
        chunk = certificate[offset:offset + 200]
        c.raw("certificate_next_put", 0xDB, 0x3F, 0xFF, chunk,
              cla=0 if offset + len(chunk) == len(certificate) else 0x10)
    read_in_chunks(c, 0xCB, 0x3F, 0xFF, bytes.fromhex("5c035fc105"), certificate)
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
        metadata = fields(c.cmd("generated_algorithm_metadata", 0xF7, 0, 0x9A))
        assert metadata[1] == bytes([IDS[a]])
        assert metadata[2] == b"\x02\x01" and metadata[3] == b"\x01"
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


def container_names(c):
    c.generate(0)
    c.generate(0, 0x95)
    c.generate(0, 0xF9)
    name = bytes.fromhex("41002d4e3dd800de")
    assert c.cmd("initial_name_empty", 0xF5, 0, 0x9A) == b""
    c.wire.command("RESET")
    c.select()
    c.cmd("name_write_requires_management", 0xF5, 1, 0x9A, name, status=0x6982)
    c.auth()
    for value in (b"A", bytes(2), bytes.fromhex("00d8"), bytes.fromhex("00dc"),
                  bytes.fromhex("00d84100"), b"X\0" * 40):
        c.cmd("invalid_container_name", 0xF5, 1, 0x9A, value, status=0x6A80)
    maximum = b"X\0" * 39
    c.cmd("maximum_container_name", 0xF5, 1, 0x9A, maximum)
    assert c.cmd("maximum_name_read", 0xF5, 0, 0x9A) == maximum
    c.cmd("unicode_container_name", 0xF5, 1, 0x9A, name)
    for slot in (0x95, 0xF9):
        c.cmd("duplicate_container_name", 0xF5, 1, slot, name, status=0x6A80)
    c.wire.command("RESET")
    c.select()
    assert c.cmd("persistent_container_name", 0xF5, 0, 0x9A) == name
    c.auth()
    before = c.cmd("named_key_metadata", 0xF7, 0, 0x9A)
    for replacement in (maximum, b""):
        c.wire.command("FAIL_WRITE 17")
        c.cmd("idempotent_name_needs_no_write", 0xF5, 1, 0x9A, name)
        c.cmd("name_commit_failure", 0xF5, 1, 0x9A, replacement, status=0x6900)
        assert c.cmd("failed_name_preserved", 0xF5, 0, 0x9A) == name
        assert c.cmd("failed_name_keeps_key", 0xF7, 0, 0x9A) == before
    c.wire.command("FAIL_WRITE 17")
    c.cmd("failed_named_key_generation", 0x47, 0, 0x9A,
          bytes.fromhex("ac03800111"), status=0x6900)
    assert c.cmd("failed_generation_keeps_name", 0xF5, 0, 0x9A) == name
    assert c.cmd("failed_generation_keeps_key", 0xF7, 0, 0x9A) == before
    old_public = c.public(0)
    exercise(c, 0, old_public)
    imported = tlv(6, bytes(31) + b"\x01")
    c.raw("named_import_first", 0xFE, 0x11, 0x9A, imported[:17], cla=0x10)
    c.raw("named_import_truncated", 0xFE, 0x11, 0x9A, imported[17:-1], status=0x6700)
    assert c.cmd("truncated_import_keeps_name", 0xF5, 0, 0x9A) == name
    assert c.cmd("truncated_import_keeps_key", 0xF7, 0, 0x9A) == before
    c.cmd("named_import_success", 0xFE, 0x11, 0x9A, imported)
    assert c.cmd("import_clears_name", 0xF5, 0, 0x9A) == b""
    exercise(c, 0, ec.derive_private_key(1, ec.SECP256R1()).public_key())
    c.cmd("rename_before_generate", 0xF5, 1, 0x9A, name)
    c.generate(0)
    assert c.cmd("generation_clears_name", 0xF5, 0, 0x9A) == b""
    c.cmd("remove_name_test_retired_key", 0xF6, 0xFF, 0x95)


def custom_p521(c):
    config = c.cmd("read_before_p521_mapping", 0xEE, 1, 0)
    custom = bytearray(config)
    custom[6] = 0x55
    c.cmd("custom_p521_mapping", 0xEE, 2, 0, bytes(custom), le=None)
    reply = c.cmd("custom_p521_generate", 0x47, 0, 0x9A,
                  bytes.fromhex("ac09800155aa0102ab0101"))
    assert len(reply) == 140 and reply[:8] == bytes.fromhex("7f49818886818504")
    metadata = fields(c.cmd("custom_p521_metadata", 0xF7, 0, 0x9A))
    assert metadata[1] == b"\x55" and metadata[2] == b"\x02\x01"
    public = pubkey(8, fields(reply)[0x7F49])
    c.verify()
    digest = hashlib.sha512(b"custom P-521 mapping").digest()
    answer = c.cmd("custom_p521_sign", 0x87, 0x55, 0x9A,
                   tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest)))
    public.verify(fields(fields(answer)[0x7C])[0x82], digest,
                  ec.ECDSA(utils.Prehashed(hashes.SHA512())))
    c.cmd("restore_p521_mapping", 0xEE, 2, 0, config, le=None)


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


def invalid_private_inputs(c):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c.import_key(5, private)
    before = c.cmd("rsa_validation_baseline", 0xF7, 0, 0x9A)
    numbers = private.private_numbers()
    components = [numbers.p, numbers.q, numbers.dmp1, numbers.dmq1, numbers.iqmp]
    for index, replacement in ((2, numbers.dmp1 ^ 0x55), (1, numbers.p)):
        changed = components.copy()
        changed[index] = replacement
        body = b"".join(tlv(i + 1, value.to_bytes(128, "big")) for i, value in enumerate(changed))
        c.cmd("reject_inconsistent_crt_import", 0xFE, 7, 0x9A, body, status=0x6A80)
        assert c.cmd("invalid_crt_keeps_key", 0xF7, 0, 0x9A) == before
    exercise(c, 5, private.public_key())
    # Compact record: header6, exponent4, p128, q128, then dp128.
    c.wire.command("CORRUPT 17 366 85")
    answer = c.cmd("reject_corrupt_stored_crt", 0x87, 7, 0x9A,
                   tlv(0x7C, tlv(0x82, b"") + tlv(0x81, (42).to_bytes(256, "big"))),
                   status=0x6900)
    assert answer == b""
    c.wire.command("CORRUPT 17 366 85")
    exercise(c, 5, private.public_key())

    private = ec.derive_private_key(1, ec.SECP256R1())
    c.import_key(0, private)
    c.verify()
    point = private.public_key().public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)
    off_curve = point[:-1] + bytes([point[-1] ^ 1])
    prime = bytes.fromhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    out_of_field = b"\x04" + prime + point[33:]
    for invalid in (off_curve, out_of_field):
        answer = c.cmd("reject_invalid_ecdh_peer", 0x87, 0x11, 0x9A,
                       tlv(0x7C, tlv(0x82, b"") + tlv(0x85, invalid)), status=0x6900)
        assert answer == b""
    exercise(c, 0, private.public_key())


def encoding_regressions(c):
    for algorithm, private, expected in encoding_vectors():
        c.import_key(algorithm, private)
        metadata = c.cmd("fixed_public_encoding", 0xf7, 0, 0x9a)
        assert fields(metadata)[4] == expected
        if algorithm == 7:
            assert len(metadata) == 536
            assert metadata[:18] == bytes.fromhex("010116020202010301020482020a81820200")
            assert metadata[-6:] == bytes.fromhex("820400010001")
            read_in_chunks(c, 0xF7, 0, 0x9A, b"", metadata)
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
            metadata = fields(c.cmd("pq_algorithm_origin", 0xF7, 0, 0x9A))
            assert metadata[1] == bytes([alg]) and metadata[3] == bytes([2 if imported else 1])
            assert metadata[4] == encoded
            assert c.wire.command("SIZE 17") == (6 + size).to_bytes(4, "big")
            public = cls.from_public_bytes(fields(encoded)[0x86])
            assert len(fields(encoded)[0x86]) == (1952 if alg == 0xE2 else 1184)
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


def pq_seed_lifecycle(c):
    config = c.cmd("read_before_custom_pq", 0xEE, 1, 0)
    custom = bytearray(config)
    custom[8:] = bytes([0x56, 0x57])
    c.cmd("custom_pq_mapping", 0xEE, 2, 0, bytes(custom))
    for algorithm, tag, size, base, cls in (
        (0x56, 9, 32, 0x80, mldsa.MLDSA65PrivateKey),
        (0x57, 10, 64, 0x40, mlkem.MLKEM768PrivateKey),
    ):
        seed = bytes(range(base, base + size))
        body = tlv(tag, seed)
        private = cls.from_seed_bytes(seed)
        c.cmd("custom_pq_import", 0xFE, algorithm, 0x9A, body)
        before = c.cmd("custom_pq_import_metadata", 0xF7, 0, 0x9A)
        meta = fields(before)
        assert meta[1] == bytes([algorithm]) and meta[3] == b"\x02"
        assert fields(meta[4])[0x86] == private.public_key().public_bytes_raw()
        c.cmd("pq_seed_explicit_policy", 0xFE, algorithm, 0x94,
              body + bytes.fromhex("aa0103ab0102"))
        assert fields(c.cmd("pq_seed_policy_metadata", 0xF7, 0, 0x94))[2] == b"\x03\x02"
        c.cmd("delete_pq_policy_key", 0xF6, 0xFF, 0x94)
        malformed = [(tlv(11, b""), 0x6A80), (tlv(tag, seed[:-1]), 0x6700)]
        if tag == 10:
            malformed.append((body + body, 0x6A80))
        for value, status in malformed:
            c.cmd("invalid_pq_seed_import", 0xFE, algorithm, 0x9A, value, status=status)
            assert c.cmd("invalid_seed_keeps_key", 0xF7, 0, 0x9A) == before
        c.wire.command("FAIL_WRITE 17")
        c.cmd("failed_pq_seed_import", 0xFE, algorithm, 0x9A,
              tlv(tag, bytes(size)), status=0x6900)
        assert c.cmd("failed_seed_keeps_key", 0xF7, 0, 0x9A) == before
        c.cmd("move_imported_pq", 0xF6, 0x95, 0x9A)
        c.cmd("moved_pq_source_missing", 0xF7, 0, 0x9A, status=0x6A88)
        c.wire.command("RESET")
        c.select()
        assert c.cmd("persistent_moved_pq", 0xF7, 0, 0x95) == before
        c.verify()
        if tag == 9:
            message = b"pq-custom"
            answer = c.cmd("custom_moved_pq_sign", 0x87, algorithm, 0x95,
                           tlv(0x7C, tlv(0x82, b"") + tlv(0x81, message)))
            private.public_key().verify(fields(fields(answer)[0x7C])[0x82], message)
        else:
            secret, ciphertext = private.public_key().encapsulate()
            answer = c.cmd("custom_moved_pq_decaps", 0x87, algorithm, 0x95,
                           tlv(0x7C, tlv(0x82, b"") + tlv(0x81, ciphertext)))
            assert fields(fields(answer)[0x7C])[0x82] == secret
        c.auth()
        c.cmd("delete_imported_pq", 0xF6, 0xFF, 0x95)
        c.cmd("deleted_pq_missing", 0xF7, 0, 0x95, status=0x6A88)
    c.cmd("restore_custom_pq_mapping", 0xEE, 2, 0, config)


def pq_replacement(c):
    for algorithm in (0xE2, 0xE3):
        body = tlv(0xAC, tlv(0x80, bytes([algorithm])))
        c.raw("pending_new_pq_key", 0x47, 0, 0x95, body, le=256, status=0x61FF)
        c.wire.command("RESET")
        c.select()
        c.cmd("aborted_new_pq_key_absent", 0xF7, 0, 0x95, status=0x6A88)
        c.auth()
        c.generate(0, 0x95)
        c.cmd("name_before_pq_replacement", 0xF5, 1, 0x95, b"M\0")
        before = c.cmd("key_before_pq_replacement", 0xF7, 0, 0x95)
        for interruption in ("select", "reset", "rejected"):
            c.raw("pending_pq_replacement", 0x47, 0, 0x95, body, le=256, status=0x61FF)
            for _ in range(5 if algorithm == 0xE2 else 2):
                c.raw("partial_pq_public", 0xC0, le=256, status=0x61FF)
            if interruption == "reset":
                c.wire.command("RESET")
            elif interruption == "rejected":
                answer, a, b = c.wire.transmit(bytes.fromhex("00fd0000000001"))
                assert not answer and (a, b) == (0x67, 0)
                c.raw("rejected_command_abandons_pq_response", 0xC0, le=256, status=0x6986)
            c.select()
            assert c.cmd("aborted_pq_keeps_key", 0xF7, 0, 0x95) == before
            assert c.cmd("aborted_pq_keeps_name", 0xF5, 0, 0x95) == b"M\0"
            c.auth()
        c.raw("pq_before_commit_failure", 0x47, 0, 0x95, body, le=256, status=0x61FF)
        c.wire.command("FAIL_WRITE 40")
        c.cmd("pq_commit_failure", 0xC0, le=256, status=0x6900)
        assert c.cmd("failed_pq_keeps_key", 0xF7, 0, 0x95) == before
        assert c.cmd("failed_pq_keeps_name", 0xF5, 0, 0x95) == b"M\0"
        generated = c.cmd("complete_pq_replacement", 0x47, 0, 0x95, body)
        metadata = fields(c.cmd("committed_pq_metadata", 0xF7, 0, 0x95))
        assert metadata[1] == bytes([algorithm]) and metadata[4] == fields(generated)[0x7F49]
        assert c.cmd("committed_pq_clears_name", 0xF5, 0, 0x95) == b""
        c.cmd("delete_pq_replacement_test_key", 0xF6, 0xFF, 0x95)


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
    config = c.cmd("read_before_disabling_stream_extension", 0xEE, 1, 0)
    c.cmd("disable_stream_extension", 0xEE, 2, 0, bytes(10), le=None)
    c.cmd("disabled_stream_rejected", 0x87, 0xFF, 0x9A,
          bytes.fromhex("7c0482008100"), status=0x6A86)
    c.cmd("restore_stream_extension", 0xEE, 2, 0, config, le=None)


def sm2_operations(c):
    c.cmd("sm2_import", 0xFE, 0x54, 0x9A, tlv(6, sm2.V_DA), le=None)
    c.verify()
    public = fields(fields(c.cmd("sm2_metadata", 0xF7, 0, 0x9A))[4])[0x86][1:]
    assert public == sm2.V_PA
    metadata = fields(c.cmd("sm2_algorithm_metadata", 0xF7, 0, 0x9A))
    assert metadata[1] == b"\x54" and metadata[3] == b"\x02"

    def verify_sm2(sig, digest):
        assert len(sig) == 64
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        assert 0 < r < sm2.N and 0 < s < sm2.N
        point = sm2.point_add(
            sm2.point_mul(s, sm2.G),
            sm2.point_mul((r + s) % sm2.N, (sm2.b2i(public[:32]), sm2.b2i(public[32:]))),
        )
        return point is not None and (int.from_bytes(digest, "big") + point[0]) % sm2.N == r

    digest = bytes(range(32))
    reply = c.cmd(
        "sm2_digest_sign", 0x87, 0x54, 0x9A, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest))
    )
    assert verify_sm2(fields(fields(reply)[0x7C])[0x82], digest)
    c.cmd("sm2_short_digest", 0x87, 0x54, 0x9A,
          tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest[:-1])), status=0x6700)
    for own in [None, b"custom SM2 identity", bytes([0xA5]) * 32]:
        message = bytes(range(256)) * 20
        reply = c.cmd(
            "sm2_stream_sign",
            0x87,
            0x54,
            0x9A,
            tlv(0x7C, (tlv(0x80, own) if own else b"") + tlv(0x82, b"") + tlv(0x81, message)),
        )
        assert verify_sm2(
            fields(fields(reply)[0x7C])[0x82],
            sm2.sm3(sm2.sm2_z(own or sm2.ID_DEFAULT, public) + message),
        )
        if own:
            assert not verify_sm2(
                fields(fields(reply)[0x7C])[0x82],
                sm2.sm3(sm2.sm2_z(sm2.ID_DEFAULT, public) + message),
            )

    def stream(body, status=0x9000):
        request = tlv(0x7C, body)
        assert not c.raw("sm2_stream_header", 0x87, 0x54, 0x9A,
                         request[:2], cla=0x10)
        return c.raw("sm2_stream_finish", 0x87, 0x54, 0x9A,
                     request[2:], status=status)

    empty = tlv(0x82, b"") + tlv(0x81, b"")
    for body in [
        tlv(0x82, b"") + tlv(0x80, b"id") + tlv(0x81, b""),
        tlv(0x80, bytes(33)) + empty,
        tlv(0x80, b"") + empty,
        tlv(0x80, b"a") + tlv(0x80, b"b") + empty,
    ]:
        assert not stream(body, 0x6A80)
    # Chaining selects full-message hashing even for short and empty messages.
    # Successful signatures also prove recovery after rejected stream templates.
    for message in [b"", bytes(range(20))]:
        reply = stream(tlv(0x82, b"") + tlv(0x81, message))
        assert verify_sm2(fields(fields(reply)[0x7C])[0x82],
                          sm2.sm3(sm2.sm2_z(sm2.ID_DEFAULT, public) + message))
    config = c.cmd("sm2_extension_config", 0xEE, 1, 0)
    c.cmd("sm2_disable_extension", 0xEE, 2, 0, bytes(10), le=None)
    assert not c.raw("sm2_disabled_stream", 0x87, 0x54, 0x9A,
                     tlv(0x7C, empty)[:2], cla=0x10, status=0x6A86)
    c.cmd("sm2_restore_extension", 0xEE, 2, 0, config, le=None)
    c.import_key(0, ec.derive_private_key(1, ec.SECP256R1()))
    assert not c.raw("sm2_wrong_key_type", 0x87, 0x54, 0x9A,
                     tlv(0x7C, empty)[:2], cla=0x10, status=0x6A86)
    c.cmd("sm2_restore_key", 0xFE, 0x54, 0x9A, tlv(6, sm2.V_DA), le=None)
    c.verify()
    exp = tlv(0x86, b"\x04" + sm2.V_PB) + tlv(0x87, b"\x04" + sm2.V_EB)
    # Cover both roles with an independent peer, custom identity binding and
    # the outer/inner BER length transitions at 125..128 derived bytes.
    for initiator, size in [(True, n) for n in (16, 32, 125, 126, 127, 128)] + [(False, 128)]:
        own, peer = (b"card-a", b"host-b-resp") if size == 32 else (sm2.ID_DEFAULT, sm2.ID_DEFAULT)
        custom = size == 32
        start = tlv(0x7C, (tlv(0x80, own) if custom else b"") + tlv(0x82, b""))
        inner = exp + (tlv(0x88, peer) if custom else b"")
        if size != 16:
            inner += tlv(0x89, size.to_bytes(2, "big"))
        if initiator:
            reply = c.cmd("sm2_initiator_start", 0x87, 0x54, 0x9A, start)
            encoded = fields(fields(reply)[0x7C])[0x82]
            assert len(encoded) == 65 and encoded[0] == 4
            eph = encoded[1:]
            reply = c.cmd("sm2_initiator_finish", 0x87, 0x54, 0x9A,
                          tlv(0x7C, tlv(0x82, b"") + tlv(0x85, inner)))
            actual = fields(fields(reply)[0x7C])[0x82]
            assert reply == tlv(0x7C, tlv(0x82, actual))
        else:
            reply = c.cmd("sm2_responder", 0x87, 0x54, 0x9A,
                          tlv(0x7C, tlv(0x82, b"") + tlv(0x85, inner)))
            values = fields(fields(reply)[0x7C])
            assert len(values[0x82]) == 65 and values[0x82][0] == 4
            eph, actual = values[0x82][1:], values[0x85]
            assert reply == tlv(0x7C, tlv(0x82, values[0x82]) + tlv(0x85, actual))
        expected = sm2.key_exchange_full(
            int(initiator), peer, own, sm2.V_DB, sm2.V_PB,
            sm2.V_RB, sm2.V_EB, public, eph, size,
        )[0]
        assert len(actual) == size and actual == expected
        if custom:
            wrong = sm2.key_exchange_full(
                1, sm2.ID_DEFAULT, sm2.ID_DEFAULT, sm2.V_DB, sm2.V_PB,
                sm2.V_RB, sm2.V_EB, public, eph, size,
            )[0]
            assert actual != wrong
    c.cmd(
        "sm2_reject_plain_ecdh",
        0x87,
        0x54,
        0x9A,
        tlv(0x7C, tlv(0x82, b"") + tlv(0x85, b"\x04" + sm2.V_PB)),
        status=0x6A80,
    )

    start = tlv(0x7C, tlv(0x82, b""))
    finish = tlv(0x7C, tlv(0x82, b"") + tlv(0x85, exp))
    invalid = [
        exp + tlv(0x89, n.to_bytes(2, "big")) for n in (0, 129)
    ] + [
        tlv(0x86, b"\x04" + sm2.V_PB) * 2,
        exp + tlv(0x8A, b""),
        exp + b"\0",
    ]
    for index in (0, 1):
        points = [bytearray(sm2.V_PB), bytearray(sm2.V_EB)]
        points[index][-1] ^= 1
        invalid.append(tlv(0x86, b"\x04" + points[0]) + tlv(0x87, b"\x04" + points[1]))
    for inner in invalid:
        assert not c.cmd("sm2_invalid_peer_template", 0x87, 0x54, 0x9A,
                         tlv(0x7C, tlv(0x82, b"") + tlv(0x85, inner)),
                         status=0x6700 if inner == exp + b"\0" else 0x6A80)
    for own in (b"", bytes(33)):
        assert not c.cmd("sm2_invalid_agreement_identity", 0x87, 0x54, 0x9A,
                         tlv(0x7C, tlv(0x80, own) + tlv(0x82, b"")), status=0x6A80)
    assert not c.cmd("sm2_missing_response_tag", 0x87, 0x54, 0x9A,
                     tlv(0x7C, tlv(0x80, b"id")), status=0x6A80)

    c.import_key(0, ec.derive_private_key(1, ec.SECP256R1()), 0x95)
    assert not c.cmd("sm2_agreement_wrong_key_type", 0x87, 0x54, 0x95, start, status=0x6A86)
    c.cmd("sm2_delete_mismatch_key", 0xF6, 0xFF, 0x95)
    assert not c.cmd("sm2_agreement_empty_slot", 0x87, 0x54, 0x95, start, status=0x6985)

    # After each interruption, a peer template must be a fresh responder
    # operation. Verify its key independently, rather than just checking SW.
    for interruption in ("restart", "identity", "sign", "verify", "select", "reset"):
        c.cmd("sm2_before_interruption", 0x87, 0x54, 0x9A, start)
        if interruption == "restart":
            assert not c.cmd("sm2_duplicate_start", 0x87, 0x54, 0x9A, start, status=0x6985)
        elif interruption == "identity":
            assert not c.cmd("sm2_change_identity_mid_session", 0x87, 0x54, 0x9A,
                             tlv(0x7C, tlv(0x80, b"x") + tlv(0x82, b"") + tlv(0x85, exp)),
                             status=0x6A80)
        elif interruption == "sign":
            reply = c.cmd("sm2_sign_interrupts_agreement", 0x87, 0x54, 0x9A,
                          tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest)))
            assert verify_sm2(fields(fields(reply)[0x7C])[0x82], digest)
        elif interruption == "verify":
            c.verify()
        else:
            if interruption == "reset":
                c.wire.command("RESET")
            c.select()
            c.verify()
        reply = fields(fields(c.cmd("sm2_recover_as_responder", 0x87, 0x54, 0x9A, finish))[0x7C])
        assert 0x85 in reply, interruption
        expected = sm2.key_exchange_full(
            0, sm2.ID_DEFAULT, sm2.ID_DEFAULT, sm2.V_DB, sm2.V_PB,
            sm2.V_RB, sm2.V_EB, public, reply[0x82][1:], 16,
        )[0]
        assert reply[0x85] == expected
    c.auth()

    # One shared initiator state must survive a responder operation on another
    # slot. Exercise both PIN_NEVER and one verification for PIN_ONCE.
    for policy in (1, 2):
        for slot, private in ((0x9A, sm2.V_DA), (0x9C, sm2.V_DB)):
            c.cmd("sm2_interleaved_import", 0xFE, 0x54, slot,
                  tlv(6, private) + tlv(0xAA, bytes([policy])), le=None)
        c.select()
        if policy == 2:
            c.verify()
        a = fields(fields(c.cmd("sm2_slot_a_start", 0x87, 0x54, 0x9A, start))[0x7C])[0x82]
        assert len(a) == 65 and a[0] == 4
        peer = tlv(0x86, b"\x04" + sm2.V_PA) + tlv(0x87, a)
        b = fields(fields(c.cmd("sm2_slot_b_respond", 0x87, 0x54, 0x9C,
                               tlv(0x7C, tlv(0x82, b"") + tlv(0x85, peer))))[0x7C])
        assert len(b[0x82]) == 65 and b[0x82][0] == 4 and len(b[0x85]) == 16
        peer = tlv(0x86, b"\x04" + sm2.V_PB) + tlv(0x87, b[0x82])
        derived = fields(fields(c.cmd("sm2_slot_a_finish", 0x87, 0x54, 0x9A,
                                     tlv(0x7C, tlv(0x82, b"") + tlv(0x85, peer))))[0x7C])
        assert derived == {0x82: b[0x85]}
        c.cmd("sm2_completed_exchange_can_restart", 0x87, 0x54, 0x9A, start)
        c.select()
        c.auth()
    c.cmd("sm2_always_import", 0xFE, 0x54, 0x9A,
          tlv(6, sm2.V_DA) + tlv(0xAA, b"\x03"), le=None)
    c.select()
    for request in (start, finish):
        assert not c.cmd("sm2_always_requires_pin", 0x87, 0x54, 0x9A,
                         request, status=0x6982)
    c.verify()
    reply = fields(fields(c.cmd("sm2_always_authorized_responder", 0x87, 0x54, 0x9A, finish))[0x7C])
    expected = sm2.key_exchange_full(
        0, sm2.ID_DEFAULT, sm2.ID_DEFAULT, sm2.V_DB, sm2.V_PB,
        sm2.V_RB, sm2.V_EB, public, reply[0x82][1:], 16,
    )[0]
    assert reply[0x85] == expected
    assert not c.cmd("sm2_always_consumed_pin", 0x87, 0x54, 0x9A, finish, status=0x6982)
    c.auth()
    c.cmd("sm2_restore_once_policy", 0xFE, 0x54, 0x9A,
          tlv(6, sm2.V_DA) + tlv(0xAA, b"\x02"), le=None)


def attestation(c):
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    c.import_key(0, issuer_key, 0xF9)
    c.cmd("issuer_container_name", 0xF5, 1, 0xF9, b"F\0")
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


def malformed_commands(c):
    # Fixed command-boundary regressions, with explicit outcomes and recovery.
    for ins, p1, p2, body in (
        (0x87, 0x0A, 0x9B, b""),
        (0x87, 0x0A, 0x9B, b"\x7c"),
        (0xCB, 0x3F, 0xFF, b""),
        (0xDB, 0x3F, 0xFF, bytes.fromhex("5c035fc1")),
        (0x47, 0, 0x9A, bytes.fromhex("ac008001")),
        (0xFE, 7, 0x9C, bytes.fromhex("013e0100")),
    ):
        c.cmd("truncated_command", ins, p1, p2, body, status=0x6700)
    c.cmd("wrong_management_template", 0x87, 0x0A, 0x9B, bytes(2), status=0x6A80)
    c.cmd("unsupported_management_algorithm", 0x87, 0xFF, 0x9B,
          bytes.fromhex("7c00"), status=0x6A86)
    c.auth()


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
    empty = bytes.fromhex("7c0482008100")
    for body, status in ((bytes.fromhex("7c058201008100"), 0x6A80),
                         (bytes.fromhex("7c0582008100"), 0x6700),
                         (empty[:3], 0x6700)):
        raw("malformed_stream_template", 0x87, 0xFF, 0x9A, body, status=status)
    assert raw("complete_stream_waits_for_final_fragment", 0x87, 0xFF, 0x9A,
               empty, cla=0x10) == b""
    answer = raw("empty_final_fragment_finishes_stream", 0x87, 0xFF, 0x9A, le=256)
    public.verify(fields(fields(answer)[0x7C])[0x82], b"")
    for rejected, status in (("00fd0000000001", 0x6700), ("80fd000000", 0x6E00)):
        raw("stream_before_rejected_command", 0x87, 0xFF, 0x9A, empty[:2], cla=0x10)
        answer, a, b = c.wire.transmit(bytes.fromhex(rejected))
        assert not answer and (a << 8 | b) == status
        raw("stale_stream_suffix_rejected", 0x87, 0xFF, 0x9A, empty[2:], status=0x6A80)
        answer = c.cmd("stream_recovers_after_rejection", 0x87, 0xFF, 0x9A, empty)
        public.verify(fields(fields(answer)[0x7C])[0x82], b"")
    raw("stream_before_algorithm_change", 0x87, 0xFF, 0x9A, empty[:2], cla=0x10)
    raw("changed_stream_algorithm_rejected", 0x87, 0xE0, 0x9A, empty[2:], status=0x6A80)
    public.verify(c.ga(3, 0x9A, b"recovered"), b"recovered")
    raw("pq_partial_public", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\xe2")), le=1, status=0x61FF)
    c.select()
    raw("abandoned_public_not_readable", 0xC0, le=256, status=0x6986)
    assert fields(c.cmd("abandoned_generation_keeps_ed25519", 0xF7, 0, 0x9A))[1] == b"\xe0"
    c.cmd("complete_pq_for_signing", 0x47, 0, 0x9A, tlv(0xAC, tlv(0x80, b"\xe2")))
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
    private = ec.derive_private_key(1, ec.SECP256R1())
    digest = hashlib.sha256(b"default slot usage").digest()
    peer = ec.derive_private_key(2, ec.SECP256R1())
    point = peer.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint)
    for slot, policy in ((0x9A, 2), (0x9C, 3), (0x9D, 2), (0x9E, 1), (0x82, 2), (0x95, 2)):
        c.cmd("clear_slot_before_default_import", 0xF6, 0xFF, slot)
        c.import_key(0, private, slot)
        assert fields(c.cmd("default_import_policy", 0xF7, 0, slot))[2] == bytes([policy, 1])
        c.verify()
        signature = c.ga(0, slot, digest)
        private.public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        c.verify()
        assert c.ga(0, slot, point, 0x85) == peer.exchange(ec.ECDH(), private.public_key())
        c.cmd("delete_default_policy_test_key", 0xF6, 0xFF, slot)
    for slot in range(0x82, 0x96):
        c.cmd("retired_slot_initially_missing", 0xF7, 0, slot, status=0x6A88)
        c.generate(0, slot)
        metadata = fields(c.cmd("retired_slot_metadata", 0xF7, 0, slot))
        assert metadata[1] == b"\x11" and metadata[2] == b"\x02\x01"
    directory = fields(c.cmd("directory", 0xF7, 1, 0))
    entries = directory[2]
    assert all(slot in entries[::6] for slot in range(0x82, 0x96))
    for slot in range(0x82, 0x96):
        c.cmd("delete_retired", 0xF6, 0xFF, slot, le=None)
        c.cmd("deleted_retired_slot_missing", 0xF7, 0, slot, status=0x6A88)
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
    config = bytes.fromhex("0122055152531554e2e3")
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
    assert c.cmd("reset_preserves_issuer_name", 0xF5, 0, 0xF9) == b"F\0"
    generated = c.cmd("generate_with_preserved_algorithm", 0x47, 0, 0x9A,
                      bytes.fromhex("ac03800122"))
    public = fields(fields(generated)[0x7F49])[0x86]
    assert len(public) == 32
    metadata = fields(c.cmd("preserved_algorithm_metadata", 0xF7, 0, 0x9A))
    assert metadata[1] == b"\x22" and fields(metadata[4])[0x86] == public
    c.cmd("restore_algorithms", 0xEE, 2, 0, original_config, le=None)


def run(wire, progress=None, report=None):
    c = Piv(wire, progress, report)
    try:
        for scenario in (
            unauthenticated_queries,
            authentication,
            host_managed_objects,
            management_rotation,
            algorithm_configuration,
            retry_configuration,
            object_capacity,
            objects,
            container_names,
            classic_keys,
            custom_p521,
            encoding_regressions,
            import_boundary_regressions,
            invalid_private_inputs,
            pq_keys,
            pq_seed_lifecycle,
            pq_replacement,
            randomized_ed25519,
            sm2_operations,
        ):
            c.report["scenario"] = scenario.__name__
            scenario(c)
        c.report["scenario"] = "attestation"
        issuer_key, issuer = attestation(c)
        for scenario in (malformed_commands, interruptions, slots):
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
