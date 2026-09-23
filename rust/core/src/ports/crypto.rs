// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, Debug)]
pub struct CryptoError;
/// Primitive operations only: authorization, padding selection and APDU policy
/// are decided by the caller. Persistence is explicitly encoded; the borrowed material has a checked native ABI.
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
    pub bytes: [u8; 2400],
}
#[cfg(feature = "piv")]
impl CryptoScratch {
    pub const fn new() -> Self {
        Self { bytes: [0; 2400] }
    }
}
#[cfg(feature = "piv")]
#[repr(C, align(8))]
pub struct HashState {
    pub bytes: [u8; 256],
}
#[cfg(feature = "piv")]
impl Default for CryptoScratch {
    fn default() -> Self {
        Self::new()
    }
}
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
    pub bytes: [u8; 1284],
}
impl KeyMaterial {
    pub const fn new() -> Self {
        Self {
            bits: 0,
            reserved: 0,
            bytes: [0; 1284],
        }
    }
}
impl Default for KeyMaterial {
    fn default() -> Self {
        Self::new()
    }
}
