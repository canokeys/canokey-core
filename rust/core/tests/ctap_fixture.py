# SPDX-License-Identifier: Apache-2.0
"""Throwaway attestation material provisioned over the real ADMIN commands."""
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

AAGUID = bytes.fromhex("244eb29ee0904e4981fe1f20f8d3b8f4")


def provision(card):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CanoKey test attestation")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.1"), bytes(650)), False)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    assert 528 < len(cert) <= 1152
    card.cmd("admin", 0xa4, 4, data=bytes.fromhex("f000000000"))
    card.cmd("verify admin", 0x20, data=b"123456")
    card.cmd("attestation key", 1, data=key.private_numbers().private_value.to_bytes(32, "big"))
    card.cmd("attestation cert", 2, data=cert)
    def verify(result, client_hash):
        assert result[3]["alg"] == -7 and result[3]["x5c"] == [cert]
        key.public_key().verify(result[3]["sig"], result[2] + client_hash, ec.ECDSA(hashes.SHA256()))
    return verify


def mixed_management(call, verify_attestation, curve=9, algorithm=-54):
    """Full public keys across mixed streamed responses, using a fresh CTAP store."""
    import hashlib
    from fido2 import cbor
    from fido2.ctap2.base import AuthenticatorData
    from fido2.ctap2.pin import PinProtocolV1

    rp = "mixed.example"
    challenge = hashlib.sha256(b"mixed management").digest()
    expected = []
    for i, alg in enumerate([algorithm, -49, -7, -49, -8, algorithm]):
        result = call(1, {1: challenge, 2: {"id": rp}, 3: {"id": bytes([i])},
                          4: [{"type": "public-key", "alg": alg}],
                          6: {"thirdPartyPayment": True}, 7: {"rk": True}})
        verify_attestation(result, challenge)
        credential = AuthenticatorData(result[2]).credential_data
        key = credential.public_key
        assert key[3] == alg
        assert key[1] == (7 if alg == -49 else 1 if alg == -8 else 2)
        assert key[-1] == (6 if alg in (-49, -8) else 1 if alg == -7 else curve)
        assert len(key[-2]) == (1952 if alg == -49 else 32)
        if alg not in (-49, -8):
            assert len(key[-3]) == 32
        expected.append(({"id": credential.credential_id, "type": "public-key"}, key))
    protocol = PinProtocolV1()
    public, secret = protocol.encapsulate(call(6, {1: 1, 2: 2})[1])
    pin = b"12345678"
    encrypted = protocol.encrypt(secret, pin.ljust(64, b"\0"))
    call(6, {1: 1, 2: 3, 3: public, 4: protocol.authenticate(secret, encrypted), 5: encrypted})
    hashed = protocol.encrypt(secret, hashlib.sha256(pin).digest()[:16])
    token = protocol.decrypt(secret, call(6, {1: 1, 2: 9, 3: public, 6: hashed, 9: 4})[2])
    params = {1: hashlib.sha256(rp.encode()).digest()}
    begin = {1: 4, 2: params, 3: 1, 4: protocol.authenticate(token, b"\x04" + cbor.encode(params))}
    # Repeat the scan to expose stale source/cursor state after the large keys.
    for _ in range(2):
        for i, (descriptor, key) in enumerate(expected):
            result = call(10, begin if i == 0 else {1: 5})
            assert result[6] == {"id": bytes([i])}
            assert result[7] == descriptor and result[8] == key
            assert result.get(9) == (6 if i == 0 else None)
        call(10, {1: 5}, status=0x30)
    call(7)
