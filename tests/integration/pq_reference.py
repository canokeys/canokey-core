# SPDX-License-Identifier: Apache-2.0
"""Independent ML-KEM-512 oracle, which cryptography does not expose.

Only the test-facing raw-key operations are adapted. Arithmetic, FIPS 203 seed
derivation and implicit rejection come from kyber-py, not the native firmware.
"""
from kyber_py.ml_kem import ML_KEM_512


class MLKEM512PublicKey:
    def __init__(self, raw):
        if len(raw) != 800:
            raise ValueError("ML-KEM-512 public key must contain800 bytes")
        self.raw = raw

    @classmethod
    def from_public_bytes(cls, raw):
        return cls(bytes(raw))

    def public_bytes_raw(self):
        return self.raw

    def encapsulate(self):
        return ML_KEM_512.encaps(self.raw)


class MLKEM512PrivateKey:
    def __init__(self, public, secret):
        self.public = public
        self.secret = secret

    @classmethod
    def from_seed_bytes(cls, seed):
        if len(seed) != 64:
            raise ValueError("ML-KEM seed must contain64 bytes")
        public, secret = ML_KEM_512._keygen_internal(seed[:32], seed[32:])
        return cls(public, secret)

    def public_key(self):
        return MLKEM512PublicKey(self.public)

    def decapsulate(self, ciphertext):
        return ML_KEM_512.decaps(self.secret, ciphertext)
