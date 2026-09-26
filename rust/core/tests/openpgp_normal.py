#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normal OpenPGP flows with independent host verification, also usable over USB.
Dedicated device only: resets OpenPGP, writes throwaway keys and restores default
OpenPGP state on successful completion. Other applets are not reset. A failure
leaves test state for inspection; rerun requires the default OpenPGP PW3.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from card_test import Card as ApduCard
from card_test import connection, fields, length, tlv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    utils,
    x25519,
)
from key_test import CURVES, pubkey

AID = bytes.fromhex("d27600012401")
REF = [0xB6, 0xB8, 0xA4]
ATTR = [
    bytes.fromhex(s)
    for s in [
        "132a8648ce3d030107",
        "132b8104000a",
        "132b81040022",
        "162b06010401da470f01",
        "122b060104019755010501",
        "010800002002",
        "010c00002002",
        "011000002002",
        "132b81040023",
    ]
]


class Card(ApduCard):
    def select(self):
        return self.cmd("select", 0xA4, 4, data=AID)

    def verify(self, mode=0x83, value=None):
        return self.cmd(
            "verify", 0x20, 0, mode, value or (b"12345678" if mode == 0x83 else b"123456"), le=None
        )

    def get(self, tag):
        return self.cmd(f"get_{tag:04x}", 0xCA, tag >> 8, tag & 255)

    def put(self, tag, b):
        return self.cmd(f"put_{tag:04x}", 0xDA, tag >> 8, tag & 255, b, le=None)

    def reset(self):
        self.select()
        self.verify()
        self.cmd("terminate", 0xE6, le=None)
        self.cmd("activate", 0x44, le=None)
        self.select()
        self.verify()

    def attrs(self, alg, role):
        a = ATTR[alg]
        if role == 1 and alg in CURVES:
            a = b"\x12" + a[1:]
        self.put(0xC1 + role, a)

    def public(self, role, generate=False):
        return fields(
            self.cmd(
                "generate" if generate else "public",
                0x47,
                0x80 if generate else 0x81,
                data=bytes([REF[role], 0]),
            )
        )[0x7F49]

    def import_key(self, alg, role, key):
        if alg in (5, 6, 7):
            v = key.private_numbers()
            width = key.key_size // 16
            parts = [v.public_numbers.e.to_bytes(4, "big")] + [
                x.to_bytes(width, "big") for x in [v.p, v.q, v.iqmp, v.dmp1, v.dmq1]
            ]
            tags = [0x91, 0x92, 0x93, 0x94, 0x95, 0x96]
        else:
            if alg in CURVES:
                value = key.private_numbers().private_value.to_bytes(
                    (key.curve.key_size + 7) // 8, "big"
                )
            else:
                value = key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            if alg == 4:
                # OpenPGP imports the scalar as a big-endian integer.
                value = value[::-1]
            parts = [value]
            tags = [0x92]
        self.cmd("import", 0xDB, 0x3F, 0xFF, import_template(role, tags, parts), le=None)


def exercise(c, alg, role, key):
    c.verify(0x81 if role == 0 else 0x82)
    if role != 1:
        message = b"Rust OpenPGP normal operation"
        if alg in (5, 6, 7):
            value = (
                bytes.fromhex("3031300d060960864801650304020105000420")
                + hashlib.sha256(message).digest()
            )
        elif alg in CURVES:
            value = hashlib.sha256(message).digest()
        else:
            value = message
        sig = c.cmd(
            "sign",
            0x2A if role == 0 else 0x88,
            0x9E if role == 0 else 0,
            0x9A if role == 0 else 0,
            value,
        )
        if alg in (5, 6, 7):
            key.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        elif alg in CURVES:
            width = len(sig) // 2
            key.verify(
                utils.encode_dss_signature(
                    int.from_bytes(sig[:width], "big"), int.from_bytes(sig[width:], "big")
                ),
                message,
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            key.verify(sig, message)
    else:
        if alg in (5, 6, 7):
            expected = b"OpenPGP decrypted message"
            value = b"\x00" + key.encrypt(expected, padding.PKCS1v15())
        else:
            peer = (
                x25519.X25519PrivateKey.generate()
                if alg == 4
                else ec.generate_private_key(CURVES[alg]())
            )
            if alg == 4:
                point = peer.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                expected = peer.exchange(key)
            else:
                point = peer.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )
                expected = peer.exchange(ec.ECDH(), key)
            value = tlv(0xA6, tlv(0x7F49, tlv(0x86, point)))
        assert c.cmd("decipher", 0x2A, 0x80, 0x86, value) == expected


def import_template(role, tags, parts):
    descriptors = b"".join(bytes([t]) + length(len(v)) for t, v in zip(tags, parts))
    return tlv(0x4d, bytes([REF[role], 0]) + tlv(0x7f48, descriptors)
               + tlv(0x5f48, b"".join(parts)))


def key_regressions(c):
    c.attrs(3, 0)
    for attributes in (bytes.fromhex("01"), bytes.fromhex("132a8648ce3d")):
        c.cmd("invalid_attributes", 0xda, 0, 0xc1, attributes, status=0x6a80)
    seed = bytes.fromhex("4adb8d21b8b7f3dd22fde3b8ebaddce1892a24a57b9e35d01067bb5af98989eb")
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    for tags, parts in (([0x92], [seed]), ([0x92, 0x99], [seed, bytes(32)])):
        c.cmd("ed_import", 0xdb, 0x3f, 0xff, import_template(0, tags, parts))
        assert fields(c.public(0))[0x86] == ed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        exercise(c, 3, 0, ed.public_key())

    c.attrs(5, 0)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c.import_key(5, 0, key)
    v = key.private_numbers()
    good = [v.public_numbers.e.to_bytes(4, "big")] + [
        x.to_bytes(128, "big") for x in (v.p, v.q, v.iqmp, v.dmp1, v.dmq1)]
    for defect in ("dp", "equal_primes"):
        parts = good.copy()
        if defect == "dp":
            value = bytearray(parts[4])
            value[50] ^= 0x55
            parts[4] = bytes(value)
        else:
            parts[2] = parts[1]
        c.cmd("invalid_crt_" + defect, 0xdb, 0x3f, 0xff,
              import_template(0, range(0x91, 0x97), parts), status=0x6a80)
        exercise(c, 5, 0, key.public_key())

    c.attrs(5, 1)
    c.cmd("logout_for_generate", 0x20, 0xff, 0x83)
    c.cmd("unauthorized_generate", 0x47, 0x80, data=bytes.fromhex("b800"), status=0x6982)
    c.verify()
    public = pubkey(5, c.public(1, True))
    c.verify(0x82)
    c.cmd("short_decipher", 0x2a, 0x80, 0x86, b"123456", status=0x6700)
    c.raw("decipher_first_fragment", 0x2a, 0x80, 0x86, bytes(254), cla=0x10)
    c.raw("decipher_invalid_padding", 0x2a, 0x80, 0x86, bytes(3), status=0x6a80)
    exercise(c, 5, 1, public)

    c.attrs(4, 1)
    private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "5a8340fb623e8536b1114ed6c468dca949578972e83cb02aaf1ce3349dca0d68")[::-1])
    c.import_key(4, 1, private)
    actual = c.cmd("x25519_wire_public", 0x47, 0x81, data=bytes.fromhex("b800"))
    assert actual == bytes.fromhex(
        "7f49228620a82e8b07b35e0bffb5d33d7ca6534f0c2b03b00f65a49aa985f116de4942153d"), actual.hex()
    exercise(c, 4, 1, private.public_key())
    c.reset()


def pin_regressions(c, wire, host):
    c.cmd("logout_pw3", 0x20, 0xff, 0x83, le=None)
    c.cmd("unauthorized_retry_policy", 0xf2, data=bytes([4, 5, 6]), status=0x6982)
    c.verify(0x81)
    c.cmd("short_pw1", 0x20, 0, 0x81, b"1234", status=0x6700)
    for status in (0x6982, 0x6982, 0x6983):
        c.cmd("wrong_pw1", 0x20, 0, 0x81, b"123465", status=status)
    c.reset()
    c.verify(0x81)
    c.select()
    c.cmd("reselect_pw1", 0x20, 0, 0x81, le=None)
    c.cmd("reselect_pw3", 0x20, 0, 0x83, le=None)
    c.cmd("change_invalid_p1", 0x24, 1, 0x81, b"123456", status=0x6a86)
    c.cmd("change_short_new_pin", 0x24, 0, 0x81, b"1234561234", status=0x6700)
    c.cmd("change_wrong_old_pin", 0x24, 0, 0x81, b"1234651234", status=0x6982)
    c.cmd("change_valid_pin", 0x24, 0, 0x81, b"123456654321")
    c.verify(0x82, b"654321")
    c.put(0xd3, b"abcdefgh")
    c.cmd("logout_before_reset", 0x20, 0xff, 0x83, le=None)
    c.cmd("reset_requires_pw3", 0x2c, 2, 0x81, b"abcdefgh123456", status=0x6982)
    c.cmd("reset_with_code", 0x2c, 0, 0x81, b"abcdefgh123456")
    c.verify(0x82)
    c.reset() # Reset code is disabled for retry-policy status checks.
    c.cmd("retry_policy_short", 0xf2, data=bytes([4, 5]), status=0x6700)
    c.cmd("retry_policy_long", 0xf2, data=bytes([4, 5, 6, 7]), status=0x6700)
    c.cmd("retry_policy", 0xf2, data=bytes([4, 5, 6]))
    assert c.get(0xc4)[4:] == bytes([4, 0, 6])
    c.cmd("pw1_policy_query", 0x20, 0, 0x81, le=None, status=0x63c4)
    c.verify(0x81)
    c.verify()
    if host:
        wire.command("FAIL_WRITE 6") # PgpPw3, after PW1/reset-code updates.
        c.cmd("failed_retry_policy", 0xf2, data=bytes([4, 5, 6]), status=0x6900)
        c.cmd("failure_revokes_authorization", 0xf2, data=bytes([4, 5, 6]), status=0x6982)
        c.verify()
    c.reset()


def run(wire, host):
    c = Card(wire)
    c.reset()
    pin_regressions(c, wire, host)
    key_regressions(c)
    assert c.get(0x4F)[:6] == AID
    assert len(c.get(0xC4)) == 7
    expected_algorithms = b""
    for role in range(3):
        for algorithm, attributes in enumerate(ATTR):
            if algorithm == 3 and role == 1 or algorithm == 4 and role != 1:
                continue
            if role == 1 and algorithm in CURVES:
                attributes = b"\x12" + attributes[1:]
            expected_algorithms += tlv(0xc1 + role, attributes)
    assert c.get(0xfa) == tlv(0xfa, expected_algorithms)
    for tag, b in [
        (0x5B, b"Doe<<Jane"),
        (0x5E, b"jane"),
        (0x5F2D, b"en"),
        (0x5F35, b"2"),
        (0x5F50, b"https://example.org/key"),
    ]:
        c.put(tag, b)
        assert c.get(tag) == b
    assert fields(fields(c.get(0x65))[0x65])[0x5B] == b"Doe<<Jane"
    assert fields(fields(c.get(0x6E))[0x6E])[0x4F][:6] == AID
    for r in range(3):
        cert = bytes((i + r) % 256 for i in range(1024))
        c.cmd("select_cert", 0xA5, r, 4, bytes.fromhex("60045c027f21"), le=None)
        c.put(0x7F21, cert)
        c.cmd("select_cert_read", 0xA5, r, 4, bytes.fromhex("60045c027f21"), le=None)
        assert c.get(0x7F21) == cert
        c.put(0xC7 + r, bytes([r + 1]) * 20)
        c.put(0xCE + r, bytes([r + 1]) * 4)
    assert len(c.get(0xC5)) == 60 and len(c.get(0xCD)) == 12
    c.cmd("change_pw1", 0x24, 0, 0x81, b"123456654321", le=None)
    c.verify(0x82, b"654321")
    c.put(0xD3, b"87654321")
    c.cmd("reset_pw1_rc", 0x2C, 0, 0x81, b"87654321123456", le=None)
    c.verify(0x82)
    c.cmd("change_pw3", 0x24, 0, 0x83, b"1234567887654321", le=None)
    c.verify(0x83, b"87654321")
    c.cmd("restore_pw3", 0x24, 0, 0x83, b"8765432112345678", le=None)
    c.verify()
    assert len(c.cmd("challenge", 0x84, le=32)) == 32
    def rsa4096_reload(role, key):
        if not host:
            return
        assert int.from_bytes(wire.command(f"SIZE {8 + role}"), "big") == 31 + 1284
        wire.command("RESET")
        c.select()
        restored = pubkey(7, c.public(role))
        assert restored.public_numbers() == key.public_numbers()
        exercise(c, 7, role, restored)
        c.verify()  # Restore ADMIN authorization for the following import/attributes.

    for alg in range(9):
        for role in range(3):
            if alg == 3 and role == 1 or alg == 4 and role != 1:
                continue
            c.attrs(alg, role)
            # Generate once per algorithm; import independently generated keys for
            # every role, including multi-APDU RSA-4096 component templates.
            if role == (1 if alg == 4 else 0):
                key = pubkey(alg, c.public(role, True))
                exercise(c, alg, role, key)
                if alg == 7:
                    rsa4096_reload(role, key)
            if alg in (5, 6, 7):
                private = rsa.generate_private_key(65537, (alg - 3) * 1024)
            elif alg in CURVES:
                private = ec.generate_private_key(CURVES[alg]())
            elif alg == 3:
                private = ed25519.Ed25519PrivateKey.generate()
            else:
                private = x25519.X25519PrivateKey.generate()
            c.import_key(alg, role, private)
            actual = pubkey(alg, c.public(role)).public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            assert actual == private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            exercise(c, alg, role, private.public_key())
            if alg == 7:
                rsa4096_reload(role, private.public_key())
        print(f"OpenPGP algorithm {alg}: generate/import/use passed", file=sys.stderr, flush=True)
    # Re-selection retains current grants; real reset clears session grants and
    # reloads persistent metadata/keys. Retry-policy boundaries use literal APDUs.
    c.select()
    c.cmd("reselect_preserves_mode82", 0x20, 0, 0x82, le=None)
    c.get(0xC1)
    c.verify()
    c.cmd("reset_pw1_admin", 0x2C, 2, 0x81, b"123456", le=None)
    c.verify(0x81)
    for index in range(3):
        for invalid in (0, 16):
            limits = bytearray([3, 3, 3])
            limits[index] = invalid
            c.cmd("invalid_retry_limit", 0xF2, data=limits, le=None, status=0x6A80)
            c.cmd("invalid_limits_keep_pw3_grant", 0x20, 0, 0x83, le=None)
    c.cmd("maximum_retry_limits", 0xF2, data=bytes([15, 15, 15]), le=None)
    c.cmd("maximum_pw1_query", 0x20, 0, 0x81, le=None, status=0x63CF)
    c.cmd("maximum_pw3_query", 0x20, 0, 0x83, le=None, status=0x63CF)
    c.verify()
    c.cmd("set_retry_limits", 0xF2, data=bytes([3, 3, 3]), le=None)
    c.verify()
    if host:
        c.attrs(0, 0)
        key = pubkey(0, c.public(0, True))
        c.put(0xD6, bytes([1, 0x20]))
        exercise(c, 0, 0, key)
        c.put(0xD6, bytes([0, 0x20]))

    if host:
        wire.command("RESET")
        c.select()
        c.verify(0x81)
        c.public(0)
    c.reset()
    c.cmd("select_admin_reset", 0xA4, 4, data=bytes.fromhex("f000000000"))
    c.cmd("verify_admin_reset", 0x20, data=b"123456", le=None)
    c.cmd("admin_reset_openpgp", 3, le=None)
    c.select()
    assert c.get(0xDE) == bytes([1, 0, 2, 0, 3, 0])
    return {"checks": len(c.checks), "cases": c.checks, "result": "pass"}


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--host")
    a.add_argument("--output")
    args = a.parse_args()
    with connection(args.host) as wire:
        report = run(wire, bool(args.host))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"checks": report["checks"], "result": report["result"]}))
