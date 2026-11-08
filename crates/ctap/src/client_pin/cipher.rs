// SPDX-License-Identifier: Apache-2.0
//! PIN/UV CBC framing over caller-owned buffers, without secret key storage.
use super::{KEY_BYTES, Protocol};

pub const BLOCK_BYTES: usize = 16;
#[derive(Clone, Copy)]
pub enum Direction {
    Encrypt,
    Decrypt,
}
pub trait Cbc {
    type Error;
    /// Calls are synchronous. Implementations own primitive scratch cleanup;
    /// callers erase plaintext/output on failure, including partial writes.
    fn aes256_cbc(
        &mut self,
        direction: Direction,
        key: &[u8; KEY_BYTES],
        iv: &[u8; BLOCK_BYTES],
        bytes: &mut [u8],
    ) -> Result<(), Self::Error>;
}
pub trait Encryption: Cbc {
    fn random_iv(&mut self, iv: &mut [u8; BLOCK_BYTES]) -> Result<(), Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    InvalidLength,
    Primitive(E),
}

fn split(protocol: Protocol, encoded: &[u8]) -> Result<([u8; BLOCK_BYTES], &[u8]), ()> {
    let prefix = protocol.iv_bytes();
    if encoded.len() < prefix || !encoded.len().is_multiple_of(BLOCK_BYTES) {
        return Err(());
    }
    let mut iv = [0x00; BLOCK_BYTES];
    if prefix != 0 {
        iv.copy_from_slice(&encoded[..prefix]);
    }
    Ok((iv, &encoded[prefix..]))
}

/// Borrowed ciphertext decodes into the existing exact-sized plaintext region.
/// Shape errors leave that region untouched; primitive failures may modify it.
pub fn decrypt_to<C: Cbc>(
    protocol: Protocol,
    key: &[u8; KEY_BYTES],
    encoded: &[u8],
    plain: &mut [u8],
    backend: &mut C,
) -> Result<(), Error<C::Error>> {
    let (iv, body) = split(protocol, encoded).map_err(|_| Error::InvalidLength)?;
    if body.len() != plain.len() {
        return Err(Error::InvalidLength);
    }
    plain.copy_from_slice(body);
    backend
        .aes256_cbc(Direction::Decrypt, key, &iv, plain)
        .map_err(Error::Primitive)
}

/// Owned ciphertext compacts its IV prefix in place. Bytes after the returned
/// plaintext length retain the existing ciphertext tail until owner cleanup.
pub fn decrypt_in_place<C: Cbc>(
    protocol: Protocol,
    key: &[u8; KEY_BYTES],
    encoded: &mut [u8],
    backend: &mut C,
) -> Result<usize, Error<C::Error>> {
    let (iv, body) = split(protocol, encoded).map_err(|_| Error::InvalidLength)?;
    let length = body.len();
    let prefix = protocol.iv_bytes();
    if prefix != 0 {
        encoded.copy_within(prefix.., 0);
    }
    backend
        .aes256_cbc(Direction::Decrypt, key, &iv, &mut encoded[..length])
        .map_err(Error::Primitive)?;
    Ok(length)
}

/// Holds only public IV metadata and a borrow of the owner's existing output.
/// Preparing before filling permits hmac-secret to keep RNG-before-MAC error
/// order. No secret or output borrow escapes the synchronous product operation.
#[must_use = "fill the plaintext and finish encryption before publishing output"]
pub struct Prepared<'a> {
    iv: [u8; BLOCK_BYTES],
    body: &'a mut [u8],
    encoded_length: usize,
}
impl Prepared<'_> {
    pub fn body_mut(&mut self) -> &mut [u8] {
        self.body
    }
    pub fn finish<C: Cbc>(
        self,
        key: &[u8; KEY_BYTES],
        backend: &mut C,
    ) -> Result<usize, Error<C::Error>> {
        backend
            .aes256_cbc(Direction::Encrypt, key, &self.iv, self.body)
            .map_err(Error::Primitive)?;
        Ok(self.encoded_length)
    }
}
pub fn prepare<'a, C: Encryption>(
    protocol: Protocol,
    plain_length: usize,
    out: &'a mut [u8],
    backend: &mut C,
) -> Result<Prepared<'a>, Error<C::Error>> {
    let prefix = protocol.iv_bytes();
    let encoded_length = plain_length
        .checked_add(prefix)
        .ok_or(Error::InvalidLength)?;
    if !plain_length.is_multiple_of(BLOCK_BYTES) || out.len() < encoded_length {
        return Err(Error::InvalidLength);
    }
    let mut iv = [0x00; BLOCK_BYTES];
    if prefix != 0 {
        backend.random_iv(&mut iv).map_err(Error::Primitive)?;
        out[..prefix].copy_from_slice(&iv);
    }
    Ok(Prepared {
        iv,
        body: &mut out[prefix..encoded_length],
        encoded_length,
    })
}
pub fn encrypt<C: Encryption>(
    protocol: Protocol,
    key: &[u8; KEY_BYTES],
    plain: &[u8],
    out: &mut [u8],
    backend: &mut C,
) -> Result<usize, Error<C::Error>> {
    let mut prepared = prepare(protocol, plain.len(), out, backend)?;
    prepared.body_mut().copy_from_slice(plain);
    prepared.finish(key, backend)
}
