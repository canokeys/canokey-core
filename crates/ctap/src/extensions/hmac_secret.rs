// SPDX-License-Identifier: Apache-2.0
//! hmac-secret preparation and output over product-owned secrets and buffers.
use crate::client_pin::{KEY_BYTES, Protocol, cipher};

pub const SALT_BYTES: usize = KEY_BYTES;
pub const MAX_SALT_BYTES: usize = 2 * SALT_BYTES;
pub const MAX_OUTPUT_BYTES: usize = cipher::BLOCK_BYTES + MAX_SALT_BYTES;

/// Synchronous product capabilities for agreement, authenticated input and
/// native CBC. Callers retain session/context admission and primitive cleanup.
pub trait Input {
    type Error;
    const INVALID_LENGTH: Self::Error;
    fn decrypt(
        &mut self,
        protocol: Protocol,
        key: &[u8; KEY_BYTES],
        encoded: &mut [u8],
    ) -> Result<(), Self::Error>;
    fn agree(
        &mut self,
        protocol: Protocol,
        peer: &[u8; 64],
        keys: &mut [u8; 64],
    ) -> Result<(), Self::Error>;
    fn authenticate(
        &mut self,
        protocol: Protocol,
        key: &[u8; KEY_BYTES],
        ciphertext: &[u8],
        auth: &[u8],
    ) -> Result<(), Self::Error>;
    fn wipe(&mut self, bytes: &mut [u8]);
}

const AES_KEY_OFFSET: usize = MAX_OUTPUT_BYTES;
/// The only state retained between assertion/enumeration responses: plaintext
/// salts followed by the AES key. The input MAC key is erased after preparation.
/// Owners call clear on cancellation/reset/drop; this type cannot be cloned.
pub struct Prepared {
    secrets: [u8; AES_KEY_OFFSET + KEY_BYTES],
    length: usize,
    protocol: Protocol,
}
impl Prepared {
    pub const fn new() -> Self {
        Self {
            secrets: [0x00; AES_KEY_OFFSET + KEY_BYTES],
            length: 0,
            protocol: Protocol::One,
        }
    }
    pub fn clear(&mut self, mut wipe: impl FnMut(&mut [u8])) {
        wipe(&mut self.secrets);
        self.length = 0;
    }
    pub fn active(&self) -> bool {
        self.length != 0
    }
    /// Validate shape before agreement. Authenticate ciphertext before writing
    /// plaintext; publish length/protocol only after CBC succeeds. Shared keys
    /// and failed candidate state are erased on every ordinary exit.
    #[inline(always)]
    pub fn prepare<B: Input>(
        &mut self,
        protocol: Protocol,
        peer: &[u8; 64],
        ciphertext: &[u8],
        auth: &[u8],
        backend: &mut B,
    ) -> Result<(), B::Error> {
        let mut keys = [0x00; 2 * KEY_BYTES];
        let result = (|| {
            let length = salt_length(protocol, ciphertext.len()).ok_or(B::INVALID_LENGTH)?;
            backend.agree(protocol, peer, &mut keys)?;
            backend.authenticate(
                protocol,
                (&keys[..KEY_BYTES]).try_into().unwrap(),
                ciphertext,
                auth,
            )?;
            let (salts, aes) = self.secrets.split_at_mut(AES_KEY_OFFSET);
            salts[..ciphertext.len()].copy_from_slice(ciphertext);
            backend.decrypt(
                protocol,
                (&keys[KEY_BYTES..]).try_into().unwrap(),
                &mut salts[..ciphertext.len()],
            )?;
            aes.copy_from_slice(&keys[KEY_BYTES..]);
            self.protocol = protocol;
            self.length = length;
            Ok(())
        })();
        backend.wipe(&mut keys);
        if result.is_err() {
            self.clear(|bytes| backend.wipe(bytes));
        }
        result
    }
    pub fn output<B: Output>(
        &self,
        credential_key: &[u8; KEY_BYTES],
        out: &mut [u8],
        backend: &mut B,
    ) -> Result<usize, cipher::Error<B::Error>> {
        output(
            self.protocol,
            self.secrets[AES_KEY_OFFSET..].try_into().unwrap(),
            credential_key,
            &self.secrets[..self.length],
            out,
            backend,
        )
    }
}

#[inline(always)]
pub fn salt_length(protocol: Protocol, encoded_length: usize) -> Option<usize> {
    let length = encoded_length.checked_sub(protocol.iv_bytes())?;
    matches!(length, SALT_BYTES | MAX_SALT_BYTES).then_some(length)
}

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
