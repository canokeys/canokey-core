// SPDX-License-Identifier: Apache-2.0
//! hmac-secret output over admitted decrypted salts and existing CBC buffers.
use crate::client_pin::{KEY_BYTES, Protocol, cipher};

pub const SALT_BYTES: usize = KEY_BYTES;
pub const MAX_SALT_BYTES: usize = 2 * SALT_BYTES;
pub const MAX_OUTPUT_BYTES: usize = cipher::BLOCK_BYTES + MAX_SALT_BYTES;

/// Products retain their HMAC primitive and primitive scratch erasure. Each
/// call writes one SHA-256 result directly into the supplied plaintext view.
pub trait Output: cipher::Encryption {
    fn mac(
        &mut self,
        key: &[u8; KEY_BYTES],
        salt: &[u8; SALT_BYTES],
        output: &mut [u8; SALT_BYTES],
    ) -> Result<(), Self::Error>;
}
/// One or two salts fill the existing ciphertext body after IV preparation.
/// Shape admission precedes RNG; RNG precedes MAC. The caller erases the
/// credential key and failed output, including partial primitive writes.
#[inline(always)]
pub fn output<B: Output>(
    protocol: Protocol,
    aes_key: &[u8; KEY_BYTES],
    credential_key: &[u8; KEY_BYTES],
    salts: &[u8],
    output: &mut [u8],
    backend: &mut B,
) -> Result<usize, cipher::Error<B::Error>> {
    if salts.len() != SALT_BYTES && salts.len() != MAX_SALT_BYTES {
        return Err(cipher::Error::InvalidLength);
    }
    let mut prepared = cipher::prepare(protocol, salts.len(), output, backend)?;
    for (salt, output) in salts
        .chunks_exact(SALT_BYTES)
        .zip(prepared.body_mut().chunks_exact_mut(SALT_BYTES))
    {
        backend
            .mac(
                credential_key,
                salt.try_into().unwrap(),
                output.try_into().unwrap(),
            )
            .map_err(cipher::Error::Primitive)?;
    }
    prepared.finish(aes_key, backend)
}
