// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, Debug)]
pub struct CryptoError;
/// Key primitive operation codes, mirrored by ck_key_operation in crypto_ops.h.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum KeyOperation {
    Generate = 0,
    Validate = 1,
    Public = 2,
    RsaPkcs1Sign = 3,
    RsaPkcs1Decipher = 4,
    Agree = 5,
    EcSign = 6,
    RsaRaw = 7,
    Sm2Exchange = 8,
}

/// Stable primitive ABI; mirrored in interfaces/rust-core/crypto_ops.h.
#[cfg(feature = "piv")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum StreamOperation {
    PublicInit = 0,
    Read = 1,
    SignInit = 2,
    SignUpdate = 3,
    SignFinal = 4,
    Abort = 5,
    DecapsulateInit = 6,
    DecapsulateUpdate = 7,
    DecapsulateFinal = 8,
    Sm2Identity = 9,
}

/// Stable primitive ABI; mirrored in interfaces/rust-core/crypto_ops.h.
#[cfg(feature = "piv")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum DigestOperation {
    Init = 0,
    Update = 1,
    Final = 2,
    Abort = 3,
}

/// Opaque native primitive state in the sole session workspace; never persisted.
#[cfg(feature = "piv")]
#[repr(C, align(8))]
pub struct CryptoScratch {
    pub bytes: [u8; CRYPTO_SCRATCH_BYTES],
}
#[cfg(feature = "piv")]
impl CryptoScratch {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CRYPTO_SCRATCH_BYTES],
        }
    }
}
#[cfg(feature = "piv")]
#[repr(C, align(8))]
pub struct HashState {
    pub bytes: [u8; HASH_STATE_BYTES],
}
#[cfg(feature = "piv")]
impl Default for CryptoScratch {
    fn default() -> Self {
        Self::new()
    }
}
/// Primitive operations only: authorization, padding selection and APDU policy
/// are decided by the caller. Persistence is explicitly encoded; the borrowed material has a checked native ABI.
pub trait Crypto {
    #[cfg(feature = "piv")]
    fn digest(
        &mut self,
        _op: DigestOperation,
        _state: &mut HashState,
        _input: &[u8],
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError)
    }
    #[cfg(feature = "piv")]
    fn piv_stream(
        &mut self,
        _operation: StreamOperation,
        _algorithm: u8,
        _scratch: &mut CryptoScratch,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError)
    }

    #[cfg(feature = "piv")]
    fn aes192(
        &mut self,
        _key: &[u8; 24],
        _input: &[u8; 16],
        _out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError)
    }

    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn key_operation(
        &mut self,
        _op: KeyOperation,
        _algorithm: u8,
        _material: &mut KeyMaterial,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError)
    }
    fn mac(
        &mut self,
        algorithm: u8,
        key: &[u8],
        input: &[u8],
        output: &mut [u8; 64],
    ) -> Result<(), CryptoError>;
    fn random(&mut self, output: &mut [u8]) -> Result<(), CryptoError>;
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], output: &mut [u8; 20]);
}
/// Audited platform erasure, separate from crypto and storage mutable borrows.
pub trait Memory {
    fn wipe(&self, bytes: &mut [u8]);
}

/// Borrowed native crypto ABI view, never serialized as a native struct.
/// `bytes` holds e[4], p/q/dp/dq/qinv[256] for RSA, or the native ECC private[66]/public[132] view. ECC signing may
/// borrow the remaining bytes as primitive scratch; storage encodes only the
/// actual private scalar.
/// The first four bytes are ephemeral native-endian ABI metadata. Keeping this
/// view in the session workspace avoids a second 1288-byte RSA stack copy.
#[repr(C, align(4))]
pub struct KeyMaterial {
    pub bits: u16,
    pub reserved: u16,
    pub bytes: [u8; key_layout::SIZE],
}
impl KeyMaterial {
    pub const fn new() -> Self {
        Self {
            bits: 0,
            reserved: 0,
            bytes: [0; key_layout::SIZE],
        }
    }
}
impl Default for KeyMaterial {
    fn default() -> Self {
        Self::new()
    }
}

/// Byte offsets in the fixed SM2 key-exchange input packet, mirrored in
/// interfaces/rust-core/crypto_ops.h. Bytes 0..32 hold our ephemeral scalar;
/// each peer point is 64 raw X||Y bytes (no 04 prefix). Each ID occupies a
/// one-byte length plus 32-byte capacity. ROLE selects initiator/responder;
/// OUTPUT_LENGTH is the requested shared-key byte count (1..128).
#[cfg(feature = "piv")]
pub mod sm2_packet {
    pub const PEER_STATIC: usize = 32;
    pub const PEER_EPHEMERAL: usize = 96;
    pub const OWN_ID: usize = 160;
    pub const PEER_ID: usize = 193;
    pub const ROLE: usize = 226;
    pub const OUTPUT_LENGTH: usize = 227;
    pub const SIZE: usize = 228;
}

/// Primitive algorithm IDs, matching canokey-crypto/include/algo.h.
pub mod alg {
    pub const P256: u8 = 0;
    pub const SECP256K1: u8 = 1;
    pub const P384: u8 = 2;
    pub const ED25519: u8 = 3;
    pub const X25519: u8 = 4;
    pub const RSA2048: u8 = 5;
    pub const RSA3072: u8 = 6;
    pub const RSA4096: u8 = 7;
    pub const P521: u8 = 8;
    pub const SM2: u8 = 9;
    pub const MLKEM768: u8 = 10;
    pub const MLDSA65: u8 = 11;
}

/// Offsets within KeyMaterial.bytes (after the native bits/reserved words).
/// C verifies the corresponding rsa_key_t/ecc_key_t offsets in key_crypto.c.
/// RSA slots hold big-endian e, p, q, dp=d mod (p-1), dq=d mod (q-1), and
/// qinv=q^-1 mod p. Here "limb" means one whole 256-byte CRT component slot,
/// not a machine-word arithmetic limb. ECC overlays the same reservation with
/// a private scalar and public coordinates; 66 bytes accommodates P-521.
/// These native workspace slots are not the compact persisted key encoding.
pub mod key_layout {
    pub const EXPONENT_BYTES: usize = 4;
    pub const RSA_LIMB_BYTES: usize = 256;
    pub const RSA_LIMBS: usize = 5;
    pub const EXPONENT: usize = 0;
    pub const P: usize = EXPONENT_BYTES;
    pub const Q: usize = P + RSA_LIMB_BYTES;
    pub const DP: usize = Q + RSA_LIMB_BYTES;
    pub const DQ: usize = DP + RSA_LIMB_BYTES;
    pub const QINV: usize = DQ + RSA_LIMB_BYTES;
    pub const SIZE: usize = QINV + RSA_LIMB_BYTES;
    pub const ECC_PRIVATE_BYTES: usize = 66;
    pub const ECC_PUBLIC: usize = ECC_PRIVATE_BYTES;
    pub const ECC_PUBLIC_BYTES: usize = 2 * ECC_PRIVATE_BYTES;
    pub const RSA_PUBLIC_EXPONENT: [u8; EXPONENT_BYTES] = [0x00, 0x01, 0x00, 0x01];
}
/// Encoded elliptic-curve point prefix, independent of applet wire tags.
pub const EC_POINT_UNCOMPRESSED: u8 = 4;

/// Buffer contracts mirrored by ck_crypto_workspace in crypto_ops.h.
pub const CRYPTO_SCRATCH_BYTES: usize = 2400;
pub const HASH_STATE_BYTES: usize = 256;
pub const RSA_OUTPUT_BYTES: usize = 512;
pub mod mlkem768 {
    pub const PUBLIC_BYTES: usize = 1184;
    pub const CIPHERTEXT_BYTES: usize = 1088;
    pub const SHARED_KEY_BYTES: usize = 32;
    pub const SEED_BYTES: usize = 64;
}
pub mod mldsa65 {
    pub const PUBLIC_BYTES: usize = 1952;
    pub const SIGNATURE_BYTES: usize = 3309;
    pub const SEED_BYTES: usize = 32;
}
