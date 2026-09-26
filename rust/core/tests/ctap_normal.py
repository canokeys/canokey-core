#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CTAP host end-to-end checks with independent python-fido2 verification.

Uses the production Rust applet and C crypto adapters through the host APDU card.
The host fixture supplies fresh touches and in-memory durable records.
"""
import argparse
import hashlib
import json
import piv_sm2 as sm2
from cryptography.hazmat.primitives.asymmetric import mldsa
from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from card_test import Card, connection
from ctap_fixture import provision, AAGUID


def run(wire):
    card = Card(wire)
    verify_attestation = provision(card)
    def verify_credential(key, message, signature):
        if key[3] == -49:
            assert key[1] == 7 and key[-1] == 6 and len(key[-2]) == 1952
            assert len(signature) == 3309
            mldsa.MLDSA65PublicKey.from_public_bytes(key[-2]).verify(signature, message)
        else:
            key.verify(message, signature)
    def select():
        assert card.cmd("select", 0xa4, 4, data=bytes.fromhex("a0000006472f0001")) == b"FIDO_2_0"
    def call(command, parameters=None, status=0):
        data = bytes([command]) + (cbor.encode(parameters) if parameters is not None else b"")
        answer = card.cmd(f"CTAP {command:02x}", 0x10, data=data, cla=0x80)
        assert answer[0] == status, (command, answer.hex(), status)
        decoded = cbor.decode(answer[1:]) if len(answer) > 1 else {}
        if command in (4, 0x0a) and len(answer) > 1:
            assert cbor.encode(decoded) == answer[1:], "CTAP discovery/management must be canonical and complete"
        return decoded
    select()
    call(13, status=0xf1)
    info = call(4)
    assert info[3] == AAGUID
    assert info[5] == 1024
    assert "FIDO_2_3" in info[1]
    assert {"minPinLength", "thirdPartyPayment"} <= set(info[2])
    assert info[4] == {"rk": True, "up": True, "alwaysUv": False,
                       "credMgmt": True, "authnrCfg": True, "clientPin": False,
                       "largeBlobs": True, "pinUvAuthToken": True,
                       "setMinPINLength": True, "makeCredUvNotRqd": True}
    assert info[4]["credMgmt"] and info[4]["largeBlobs"] and info[11] == 4096
    # No-PIN policy changes must update advertised protocols and survive reset.
    assert info[4]["clientPin"] is False and info[4]["alwaysUv"] is False
    assert "U2F_V2" in info[1]
    call(13, {1: 2})
    enabled = call(4)
    assert enabled[4]["alwaysUv"] is True and "U2F_V2" not in enabled[1]
    wire.command("RESET")
    select()
    assert call(4) == enabled
    call(13, {1: 2})
    assert call(4) == info
    rp = "example.com"
    client_hash = hashlib.sha256(b"registration challenge").digest()
    assertion_hash = hashlib.sha256(b"authentication challenge").digest()
    user = {"id": b"user", "name": "user@example.com", "displayName": "Example"}
    credentials = []
    for algorithm in [-7, -8]:
        request = {1: client_hash, 2: {"id": rp, "name": "Example"}, 3: user,
                   4: [{"type": "public-key", "alg": -999}, {"type": "public-key", "alg": algorithm}]}
        result = call(1, request)
        assert result[1] == "packed" and result[3]["alg"] == -7
        auth = AuthenticatorData(result[2])
        assert auth.rp_id_hash == hashlib.sha256(rp.encode()).digest() and auth.is_user_present()
        key = auth.credential_data.public_key
        verify_attestation(result, client_hash)
        descriptor = {"id": auth.credential_data.credential_id, "type": "public-key"}
        assert len(descriptor["id"]) == 34
        answer = call(2, {1: rp, 2: assertion_hash, 3: [descriptor]})
        key.verify(answer[2] + assertion_hash, answer[3])
        assert answer[1] == descriptor and AuthenticatorData(answer[2]).counter > auth.counter
        call(2, {1: "other.example", 2: assertion_hash, 3: [descriptor]}, 0x2e)
        corrupt = dict(descriptor, id=bytes([descriptor["id"][0] ^ 1]) + descriptor["id"][1:])
        call(2, {1: rp, 2: assertion_hash, 3: [corrupt]}, 0x2e)
        call(1, request | {5: [descriptor]}, 0x19)
        credentials.append((descriptor, key))
    assert wire.command("SIZE 78") == (32).to_bytes(4, "big")
    assert wire.command("SIZE 79") == (4).to_bytes(4, "big")
    wire.command("RESET")
    select()
    descriptor, key = credentials[0]
    answer = call(2, {1: rp, 2: assertion_hash, 3: [descriptor], 5: {"up": False}})
    key.verify(answer[2] + assertion_hash, answer[3])
    assert not AuthenticatorData(answer[2]).is_user_present()

    resident_keys = {}
    for identity in [b"first", b"second"]:
        result = call(1, {1: client_hash, 2: {"id": rp}, 3: user | {"id": identity},
                          4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}})
        auth = AuthenticatorData(result[2])
        resident_keys[auth.credential_data.credential_id] = auth.credential_data.public_key
    first = call(2, {1: rp, 2: assertion_hash})
    assert first[5] == 2 and first[4] == {"id": b"first"}
    resident_keys[first[1]["id"]].verify(first[2] + assertion_hash, first[3])
    second = call(8)
    assert 5 not in second and second[4] == {"id": b"second"}
    resident_keys[second[1]["id"]].verify(second[2] + assertion_hash, second[3])
    call(8, status=0x30)
    call(2, {1: rp, 2: assertion_hash})
    call(4)
    call(8, status=0x30) # any intervening command invalidates enumeration
    call(2, {1: rp, 2: assertion_hash})
    card.cmd("deselect FIDO", 0xa4, 4, data=bytes.fromhex("f000000000"))
    select()
    call(8, status=0x30)
    old = first[1]
    call(1, {1: client_hash, 2: {"id": rp}, 3: {"id": b"first"},
             4: [{"type": "public-key", "alg": -8}], 7: {"rk": True}})
    call(2, {1: rp, 2: assertion_hash, 3: [old]}, 0x2e)
    assert int.from_bytes(wire.command("SIZE 80"), "big") < 120
    assert wire.command("SIZE 82") == bytes.fromhex("ffffffff")

    request = {1: client_hash, 2: {"id": "blob.example"}, 3: user,
               4: [{"type": "public-key", "alg": -7}], 6: {"largeBlobKey": True, "credBlob": b"stored blob"}}
    call(1, request, 0x2c)
    result = call(1, request | {7: {"rk": True}})
    assert AuthenticatorData(result[2]).extensions == {"credBlob": True}
    blob_key = result[5]
    assert len(blob_key) == 32
    blob_auth = AuthenticatorData(result[2])
    blob_descriptor = {"id": blob_auth.credential_data.credential_id, "type": "public-key"}
    assert call(2, {1: "blob.example", 2: assertion_hash, 3: [blob_descriptor]})[7] == blob_key
    wire.command("RESET")
    select()
    blob_assertion = call(2, {1: "blob.example", 2: assertion_hash, 4: {"credBlob": True}})
    assert blob_assertion[7] == blob_key
    assert AuthenticatorData(blob_assertion[2]).extensions == {"credBlob": b"stored blob"}
    blob_auth.credential_data.public_key.verify(blob_assertion[2] + assertion_hash, blob_assertion[3])
    for resident, value in [(False, b"small"), (True, b"x" * 33), (True, b"y" * 512)]:
        rejected = call(1, request | {2: {"id": "rejected.example"}, 6: {"credBlob": value}, 7: {"rk": resident}})
        rejected_auth = AuthenticatorData(rejected[2])
        assert rejected_auth.extensions == {"credBlob": False}
        if resident:
            # Oversized input must not persist its truncated 32-byte prefix.
            wire.command("RESET")
            select()
            answer = call(2, {1: "rejected.example", 2: assertion_hash, 4: {"credBlob": True}})
            assert AuthenticatorData(answer[2]).extensions == {"credBlob": b""}
            rejected_auth.credential_data.public_key.verify(answer[2] + assertion_hash, answer[3])


    # Enterprise attestation is unsupported; wrong CBOR types remain distinct.
    registration = {1: client_hash, 2: {"id": rp}, 3: user,
                    4: [{"type": "public-key", "alg": -7}]}
    for enterprise, status in [(1, 2), (2, 2), (3, 2), (-1, 0x11), (True, 0x11)]:
        call(1, registration | {10: enterprise}, status)

    salts = hashlib.sha256(b"salt one").digest() + hashlib.sha256(b"salt two").digest()
    hmac_results = {}
    for protocol, algorithm in [(PinProtocolV1(), -7), (PinProtocolV2(), -49)]:
        public, secret = protocol.encapsulate(call(6, {1: protocol.VERSION, 2: 2})[1])
        def hmac_input(value):
            encrypted = protocol.encrypt(secret, value)
            return {1: public, 2: encrypted, 3: protocol.authenticate(secret, encrypted), 4: protocol.VERSION}
        extension = hmac_input(salts)
        for extensions in [{"hmac-secret-mc": extension},
                           {"hmac-secret": False, "hmac-secret-mc": extension}]:
            call(1, registration | {6: extensions}, 0x14)
        result = call(1, {1: client_hash, 2: {"id": rp}, 3: user,
                         4: [{"type": "public-key", "alg": algorithm}],
                         6: {"hmac-secret": True, "hmac-secret-mc": extension}})
        auth = AuthenticatorData(result[2])
        assert auth.extensions["hmac-secret"] is True
        verify_attestation(result, client_hash)
        handle = {"id": auth.credential_data.credential_id, "type": "public-key"}
        expected = protocol.decrypt(secret, auth.extensions["hmac-secret-mc"])
        assert len(expected) == 64 and expected[:32] != expected[32:]
        request = {1: rp, 2: assertion_hash, 3: [handle], 4: {"hmac-secret": extension}}
        result = call(2, request)
        assert result[1] == handle
        verify_credential(auth.credential_data.public_key, result[2]+assertion_hash, result[3])
        assert protocol.decrypt(secret, AuthenticatorData(result[2]).extensions["hmac-secret"]) == expected
        single = call(2, request | {4: {"hmac-secret": hmac_input(salts[:32])}})
        assert protocol.decrypt(secret, AuthenticatorData(single[2]).extensions["hmac-secret"]) == expected[:32]
        call(2, request | {5: {"up": False}}, 0x2b)
        call(2, request | {4: {"hmac-secret": extension | {3: bytes(len(extension[3]))}}}, 0x33)
        call(2, request | {4: {"hmac-secret": extension | {1: public | {-2: bytes(32), -3: bytes(32)}}}}, 2)
        # The extension keeps prepared salts/keys across getNextAssertion only.
        first = call(2, {1: rp, 2: assertion_hash, 4: {"hmac-secret": extension}})
        second = call(8)
        assert len(protocol.decrypt(secret, AuthenticatorData(second[2]).extensions["hmac-secret"])) == 64
        for answer in [first, second]:
            direct = call(2, {1: rp, 2: assertion_hash, 3: [answer[1]], 4: {"hmac-secret": extension}})
            assert protocol.decrypt(secret, AuthenticatorData(direct[2]).extensions["hmac-secret"]) == protocol.decrypt(secret, AuthenticatorData(answer[2]).extensions["hmac-secret"])
        # Cross-protocol and reset stability on one of the original credentials.
        stable = call(2, {1: rp, 2: assertion_hash, 3: [descriptor], 4: {"hmac-secret": extension}})
        hmac_results[protocol.VERSION] = protocol.decrypt(secret, AuthenticatorData(stable[2]).extensions["hmac-secret"])
        wire.command("RESET")
        select()
    assert hmac_results[1] == hmac_results[2]

    # A nonresident payment credential reports the flag only on assertion.
    payment = call(1, {1: client_hash, 2: {"id": "pay.example"}, 3: user,
                       4: [{"type": "public-key", "alg": -7}],
                       6: {"thirdPartyPayment": True}})
    payment_auth = AuthenticatorData(payment[2])
    assert payment_auth.extensions is None
    verify_attestation(payment, client_hash)
    payment_handle = {"id": payment_auth.credential_data.credential_id, "type": "public-key"}
    payment_answer = call(2, {1: "pay.example", 2: assertion_hash, 3: [payment_handle],
                              4: {"thirdPartyPayment": True}})
    assert AuthenticatorData(payment_answer[2]).extensions == {"thirdPartyPayment": True}
    payment_auth.credential_data.public_key.verify(payment_answer[2]+assertion_hash, payment_answer[3])

    pin = b"12345678"
    for protocol in [PinProtocolV1(), PinProtocolV2()]:
        version = protocol.VERSION
        peer = call(6, {1: version, 2: 2})[1]
        public, secret = protocol.encapsulate(peer)
        if version == 1:
            encrypted = protocol.encrypt(secret, pin.ljust(64, b"\0"))
            call(6, {1: version, 2: 3, 3: public, 4: protocol.authenticate(secret, encrypted), 5: encrypted})
        hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
        token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 0x22, 10: rp})[2])
        params = {1: rp, 2: assertion_hash, 3: [descriptor], 6: protocol.authenticate(token, assertion_hash), 7: version}
        call(2, params | {1: "wrong.example"}, 0x33) # token RP mismatch, not credential lookup
        answer = call(2, params)
        key.verify(answer[2] + assertion_hash, answer[3])
        assert AuthenticatorData(answer[2]).is_user_verified()
        call(2, params, 0x33) # credential use consumed GA/ACFG permissions
        token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 2, 10: rp})[2])
        encrypted = protocol.encrypt(secret, salts)
        extension = {1: public, 2: encrypted, 3: protocol.authenticate(secret, encrypted), 4: version}
        verified = call(2, params | {4: {"hmac-secret": extension}, 6: protocol.authenticate(token, assertion_hash)})
        verified_output = protocol.decrypt(secret, AuthenticatorData(verified[2]).extensions["hmac-secret"])
        assert verified_output != hmac_results[version]
        if version == 1:
            verified_baseline = verified_output
        else:
            assert verified_output == verified_baseline

        token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 0x20})[2])
        message = b"\xff" * 32 + b"\x0d\x02"
        config = {1: 2, 3: version, 4: protocol.authenticate(token, message)}
        call(13, config)
        assert call(4)[4]["alwaysUv"] is True
        call(2, {1: rp, 2: assertion_hash, 3: [descriptor]}, 0x36)
        call(13, config)
        assert call(4)[4]["alwaysUv"] is False
    token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 4})[2])
    def manage(subcommand, params=None, status=0):
        request = {1: subcommand}
        if params is not None:
            request[2] = params
        if subcommand not in [3, 5]:
            message = bytes([subcommand]) + (cbor.encode(params) if params is not None else b"")
            request.update({3: version, 4: protocol.authenticate(token, message)})
        return call(0x0a, request, status)
    manage(3, status=0x30)
    assert manage(1) == {1: 4, 2: 96}
    # Restarting enumeration must preserve each selected RP/hash despite scans
    # of differently-sized records, while grouping duplicate RP records once.
    for _ in range(2):
        info = manage(2)
        assert info == {3: {"id": rp}, 4: hashlib.sha256(rp.encode()).digest(), 5: 3}
        for name in ["blob.example", "rejected.example"]:
            assert manage(3) == {3: {"id": name}, 4: hashlib.sha256(name.encode()).digest()}
        manage(3, status=0x30)
    first = manage(4, {1: hashlib.sha256(rp.encode()).digest()})
    assert first[9] == 2 and first[6]["id"] == b"first"
    second = manage(5)
    assert second[6]["id"] == b"second"
    manage(5, status=0x30)
    manage(4, {1: hashlib.sha256(rp.encode()).digest()})
    card.cmd("deselect FIDO management", 0xa4, 4, data=bytes.fromhex("f000000000"))
    select()
    manage(5, status=0x30)
    # Applet switching also revokes the token and key agreement.
    manage(1, status=0x33)
    public, secret = protocol.encapsulate(call(6, {1: version, 2: 2})[1])
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 4})[2])
    manage(7, {2: first[7], 3: {"id": b"wrong", "name": "Changed"}}, 2)
    manage(7, {2: first[7], 3: {"id": b"first", "name": "Changed", "displayName": "改" * 30}})
    updated = manage(4, {1: hashlib.sha256(rp.encode()).digest(), 0x80: True})
    assert updated[6] == {"id": b"first", "name": "Changed", "displayName": "改" * 21}
    assert 8 not in updated and updated[0x80] == -8
    manage(6, {2: first[7]})
    assert manage(1) == {1: 3, 2: 97}
    call(2, {1: rp, 2: assertion_hash, 3: [first[7]]}, 0x2e)
    blob_entry = manage(4, {1: hashlib.sha256(b"blob.example").digest()})
    assert blob_entry[11] == blob_key
    manage(6, {2: blob_descriptor})
    wire.command("RESET")
    select()
    remaining = call(2, {1: rp, 2: assertion_hash})
    assert remaining[4] == {"id": b"second"}
    resident_keys[remaining[1]["id"]].verify(remaining[2] + assertion_hash, remaining[3])
    protocol = PinProtocolV2()
    version = protocol.VERSION
    public, secret = protocol.encapsulate(call(6, {1: version, 2: 2})[1])
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 0x20})[2])
    policy = {1: 6, 2: [rp]}
    message = b"\xff" * 32 + b"\x0d\x03" + cbor.encode(policy)
    call(13, {1: 3, 2: policy, 3: version, 4: protocol.authenticate(token, message)})
    for origin in [rp, "unauthorized.example"]:
        request = {1: client_hash, 2: {"id": origin}, 3: user,
                   4: [{"type": "public-key", "alg": -7}],
                   6: {"credProtect": 2, "minPinLength": True}}
        result = call(1, request)
        auth = AuthenticatorData(result[2])
        assert auth.extensions == ({"credProtect": 2, "minPinLength": 6} if origin == rp else {"credProtect": 2})
        verify_attestation(result, client_hash)
    call(1, request | {4: [{"alg": -7}]}, 0x14)
    call(1, request | {4: [{"type": "public-key"}]}, 0x14)
    call(2, {1: rp, 2: assertion_hash, 3: [{"id": descriptor["id"]}]}, 0x14)
    empty = b"\x80" + hashlib.sha256(b"\x80").digest()[:16]
    assert call(12, {1: 960, 3: 0})[1] == empty
    for protocol in [PinProtocolV1(), PinProtocolV2()]:
        version = protocol.VERSION
        public, secret = protocol.encapsulate(call(6, {1: version, 2: 2})[1])
        hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
        token = protocol.decrypt(secret, call(6, {1: version, 2: 9, 3: public, 6: hashed, 9: 0x10})[2])
        def write_blob(fragment, offset, length=None, status=0, byteorder="little"):
            message = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, byteorder) + hashlib.sha256(fragment).digest()
            params = {2: fragment, 3: offset, 5: protocol.authenticate(token, message), 6: version}
            if length is not None:
                params[4] = length
            return call(12, params, status)
        body = cbor.encode([bytes(range(256)) * 5])
        blob = body + hashlib.sha256(body).digest()[:16]
        write_blob(blob[:700], 0, len(blob))
        write_blob(blob[700:-8], 700) # checksum split across fragments
        write_blob(blob[-8:], len(blob)-8)
        assert call(12, {1: 960, 3: 0})[1] == blob[:960]
        assert call(12, {1: 960, 3: 960})[1] == blob[960:]
        assert call(12, {1: 1, 3: len(blob)})[1] == b""
        write_blob(blob[:700], 0, len(blob))
        write_blob(blob[700:], 700, status=0x33, byteorder="big")
        assert call(12, {1: 960, 3: 0})[1] == blob[:960]
        write_blob(blob[:700], 0, len(blob))
        write_blob(blob[701:], 701, status=4)
        write_blob(empty[:-1] + bytes([empty[-1] ^ 1]), 0, len(empty), status=0x3d)
        assert call(12, {1: 960, 3: 0})[1] == blob[:960]
        write_blob(empty[:1], 0, len(empty))
        wire.command("RESET")
        select()
        assert call(12, {1: 960, 3: 960})[1] == blob[960:]
    # Maximal user metadata and extensions exceed the 528-byte output workspace.
    protocol = PinProtocolV2()
    public, secret = protocol.encapsulate(call(6, {1: 2, 2: 2})[1])
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    def permission(mask):
        return protocol.decrypt(secret, call(6, {1: 2, 2: 9, 3: public, 6: hashed, 9: mask, 10: "full.example"})[2])
    full_keys, full_blob_keys = {}, {}
    for payment in [False, True]:
        extensions = {"credBlob": b"b" * 32, "largeBlobKey": True, "hmac-secret": True}
        if payment:
            extensions["thirdPartyPayment"] = True
        token = permission(1)
        registration = {1: client_hash, 2: {"id": "full.example"},
                        3: {"id": bytes([payment]) * 64, "name": "n" * 64, "displayName": "d" * 64},
                        4: [{"type": "public-key", "alg": -7 if payment else -49}], 6: extensions, 7: {"rk": True},
                        8: protocol.authenticate(token, client_hash), 9: 2}
        if not payment:
            call(1, registration | {6: extensions | {"thirdPartyPayment": False}}, 0x2c)
        result = call(1, registration)
        auth = AuthenticatorData(result[2])
        full_keys[auth.credential_data.credential_id] = auth.credential_data.public_key
        verify_attestation(result, client_hash)
        assert auth.is_user_verified()
        full_blob_keys[auth.credential_data.credential_id] = result[5]
    token = permission(2)
    encrypted = protocol.encrypt(secret, salts)
    result = call(2, {1: "full.example", 2: assertion_hash,
                     4: {"credBlob": True, "thirdPartyPayment": True,
                         "hmac-secret": {1: public, 2: encrypted, 3: protocol.authenticate(secret, encrypted), 4: 2}},
                     6: protocol.authenticate(token, assertion_hash), 7: 2})
    following = call(8)
    for answer, payment in [(result, False), (following, True)]:
        assert len(cbor.encode(answer)) + 1 > 528
        auth = AuthenticatorData(answer[2])
        assert auth.extensions["credBlob"] == b"b" * 32
        assert auth.extensions["thirdPartyPayment"] is payment
        assert len(protocol.decrypt(secret, auth.extensions["hmac-secret"])) == 64
        assert len(answer[4]["name"]) == len(answer[4]["displayName"]) == 64
        assert answer[7] == full_blob_keys[answer[1]["id"]]
        verify_credential(full_keys[answer[1]["id"]], answer[2]+assertion_hash, answer[3])
    call(8, status=0x30)
    # SM2 follows the C wire contract: curve 9, alg -54, raw r||s,
    # SM3(ZA || authData || clientDataHash), with the standard identity.
    assert {"alg": -54, "type": "public-key"} in call(4)[10]
    token = permission(1)
    registration = {1: client_hash, 2: {"id": "full.example"}, 3: {"id": b"sm2"},
                    4: [{"type": "public-key", "alg": -54}], 7: {"rk": True},
                    8: protocol.authenticate(token, client_hash), 9: 2}
    result = call(1, registration)
    auth = AuthenticatorData(result[2])
    cose = auth.credential_data.public_key
    assert cose[1] == 2 and cose[3] == -54 and cose[-1] == 9
    sm2_public = cose[-2] + cose[-3]
    sm2_handle = {"id": auth.credential_data.credential_id, "type": "public-key"}
    def verify_sm2(message, signature):
        assert len(signature) == 64
        digest = sm2.sm3(sm2.sm2_z(sm2.ID_DEFAULT, sm2_public) + message)
        r, t = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        assert 0 < r < sm2.N and 0 < t < sm2.N and (r + t) % sm2.N != 0
        point = sm2.point_add(sm2.point_mul(t, sm2.G),
                             sm2.point_mul((r + t) % sm2.N, (sm2.b2i(cose[-2]), sm2.b2i(cose[-3]))))
        assert point is not None and (int.from_bytes(digest, "big") + point[0]) % sm2.N == r
    assert result[3]["alg"] == -7
    verify_attestation(result, client_hash)
    assertion = call(2, {1: "full.example", 2: assertion_hash, 3: [sm2_handle]})
    verify_sm2(assertion[2] + assertion_hash, assertion[3])
    call(2, {1: "other.example", 2: assertion_hash, 3: [sm2_handle]}, 0x2e)
    tampered = sm2_handle | {"id": b"\x00" + sm2_handle["id"][1:]}
    call(2, {1: "full.example", 2: assertion_hash, 3: [tampered]}, 0x2e)
    token = permission(4)
    entries = [manage(4, {1: hashlib.sha256(b"full.example").digest()})]
    entries.extend(manage(5) for _ in range(entries[0][9] - 1))
    stored = next(entry for entry in entries if entry[7] == sm2_handle)
    assert stored[8] == cose
    for entry in entries:
        if entry[7] != sm2_handle:
            assert entry[8] == full_keys[entry[7]["id"]]
    metadata = [manage(4, {1: hashlib.sha256(b"full.example").digest(), 0x80: True})]
    metadata.extend(manage(5) for _ in range(metadata[0][9]-1))
    assert len(metadata) == 3
    for entry in metadata:
        assert 8 not in entry
        assert entry[0x80] == (-54 if entry[7] == sm2_handle else full_keys[entry[7]["id"]][3])
        assert entry[12] is (entry[6]["id"] == b"\x01" * 64)
    wire.command("RESET")
    select()
    assertion = call(2, {1: "full.example", 2: assertion_hash, 3: [sm2_handle]})
    verify_sm2(assertion[2] + assertion_hash, assertion[3])
    # Set and clear forcePINChange through authenticated configuration/PIN commands.
    protocol = PinProtocolV2()
    public, secret = protocol.encapsulate(call(6, {1: 2, 2: 2})[1])
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    token = permission(0x20)
    policy = {3: True}
    message = b"\xff" * 32 + b"\x0d\x03" + cbor.encode(policy)
    call(13, {1: 3, 2: policy, 3: 2, 4: protocol.authenticate(token, message)})
    forced = call(4)
    assert forced[12] is True
    wire.command("RESET")
    select()
    assert call(4) == forced
    public, secret = protocol.encapsulate(call(6, {1: 2, 2: 2})[1])
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    call(6, {1: 2, 2: 9, 3: public, 6: hashed, 9: 0x20}, 0x37)
    encrypted = protocol.encrypt(secret, pin.ljust(64, b"\0"))
    call(6, {1: 2, 2: 4, 3: public, 4: protocol.authenticate(secret, encrypted + hashed),
             5: encrypted, 6: hashed})
    assert call(4)[12] is False
    return {"passed": True, "algorithms": ["ES256", "Ed25519", "SM2", "ML-DSA-65"], "checks": len(card.checks)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    with connection(args.host) as wire:
        print(json.dumps(run(wire), indent=2))


if __name__ == "__main__":
    main()
