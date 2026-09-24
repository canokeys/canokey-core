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
