// SPDX-License-Identifier: Apache-2.0
//! Authenticated credential ID layout and HMAC transcripts; no key storage.

pub const ALGORITHM_OFFSET: usize = 0;
pub const POLICY_OFFSET: usize = 1;
pub const NONCE_OFFSET: usize = 2;
pub const NONCE_BYTES: usize = 16;
pub const TAG_OFFSET: usize = NONCE_OFFSET + NONCE_BYTES;
pub const TAG_BYTES: usize = 16;
pub const ID_BYTES: usize = TAG_OFFSET + TAG_BYTES;
pub const KEY_BYTES: usize = 32;
pub const RP_HASH_BYTES: usize = 32;
pub const SM2_SETTINGS_BYTES: usize = 8;
pub const HANDLE_TRANSCRIPT_MAX_BYTES: usize = 1 + TAG_OFFSET + RP_HASH_BYTES + SM2_SETTINGS_BYTES;
pub const EXTENSION_TRANSCRIPT_BYTES: usize = 1 + ID_BYTES + RP_HASH_BYTES;
pub const RESIDENT: u8 = 0x04;
pub const CRED_PROTECT_MASK: u8 = 0x03;
pub const THIRD_PARTY_PAYMENT: u8 = 0x10;
pub type Id = [u8; ID_BYTES];

/// CanoKey credential ID byte 0, distinct from native algorithm IDs and COSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    P256 = 0x00,
    Ed25519 = 0x01,
    Sm2 = 0x02,
    MlDsa65 = 0x03,
    MlDsa44 = 0x04,
}
impl Scheme {
    pub fn decode(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::P256),
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::Sm2),
            0x03 => Some(Self::MlDsa65),
            0x04 => Some(Self::MlDsa44),
            _ => None,
        }
    }
}
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum HandleDomain {
    Tag = 0x00,
    Seed = 0x01,
}
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum ExtensionDomain {
    LargeBlobKey = 0x02,
    HmacSecretWithoutUv = 0x03,
    HmacSecretWithUv = 0x04,
}

/// HMAC-SHA-256 over exactly the supplied transcript. The capability is
/// synchronous, cannot retain key/input/output borrows, and owns primitive
/// scratch cleanup. The product owns output/root erasure and failure policy.
pub trait Mac {
    type Error;
    fn hmac_sha256(
        &mut self,
        root: &[u8; KEY_BYTES],
        transcript: &Transcript<'_>,
        out: &mut [u8; KEY_BYTES],
    ) -> Result<(), Self::Error>;
}

/// Borrowed domain || ID prefix/full ID || RP hash || optional SM2 settings.
/// Handle tags/seeds use the first 18 ID bytes. Extensions use all 34 bytes
/// and never append SM2 settings. These are storage/key derivation transcripts,
/// not a CTAP wire message, transaction marker or local integrity checksum.
pub struct Transcript<'a> {
    domain: u8,
    id: &'a [u8],
    rp: &'a [u8; RP_HASH_BYTES],
    settings: &'a [u8],
}
impl Transcript<'_> {
    /// Stream into a software MAC without materializing another input buffer.
    pub fn for_each_part(&self, mut append: impl FnMut(&[u8])) {
        append(core::slice::from_ref(&self.domain));
        append(self.id);
        append(self.rp);
        append(self.settings);
    }
    /// Native contiguous-input MACs lend their existing bounded message buffer.
    /// Insufficient space fails before changing any output bytes.
    pub fn copy_to(&self, out: &mut [u8]) -> Option<usize> {
        let length = 1 + self.id.len() + self.rp.len() + self.settings.len();
        if out.len() < length {
            return None;
        }
        let mut offset = 0;
        self.for_each_part(|part| {
            out[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        });
        Some(length)
    }
}

/// The product supplies SM2 settings only for an admitted SM2 handle, preserving
/// its existing algorithm/setting policy and tag/seed validation order.
pub fn derive_handle<M: Mac>(
    root: &[u8; KEY_BYTES],
    id: &Id,
    rp: &[u8; RP_HASH_BYTES],
    domain: HandleDomain,
    sm2_settings: Option<&[u8; SM2_SETTINGS_BYTES]>,
    out: &mut [u8; KEY_BYTES],
    mac: &mut M,
) -> Result<(), M::Error> {
    let transcript = Transcript {
        domain: domain as u8,
        id: &id[..TAG_OFFSET],
        rp,
        settings: sm2_settings.map_or(&[][..], |settings| settings.as_slice()),
    };
    mac.hmac_sha256(root, &transcript, out)
}
pub fn derive_extension<M: Mac>(
    root: &[u8; KEY_BYTES],
    id: &Id,
    rp: &[u8; RP_HASH_BYTES],
    domain: ExtensionDomain,
    out: &mut [u8; KEY_BYTES],
    mac: &mut M,
) -> Result<(), M::Error> {
    let transcript = Transcript {
        domain: domain as u8,
        id,
        rp,
        settings: &[],
    };
    mac.hmac_sha256(root, &transcript, out)
}
