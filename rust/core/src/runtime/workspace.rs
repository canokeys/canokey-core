// SPDX-License-Identifier: Apache-2.0
//! One session-owned workspace, lent by the registry to the selected applet.
//! Key material, crypto input and result are simultaneously live at the crypto
//! boundary. Certificates and encoded import messages never occupy this area.
use crate::ports::{KeyMaterial, Memory};
/// Byte offsets in retained SM2 exchange state, separate from the primitive
/// input packet: our ephemeral scalar, our ephemeral/static public X||Y,
/// then our length-prefixed identity. No SEC1 04 point prefixes are stored.
#[cfg(feature = "piv")]
pub mod agreement_layout {
    pub const SCALAR: usize = 0;
    pub const SCALAR_BYTES: usize = 32;
    pub const EPHEMERAL_PUBLIC: usize = SCALAR + SCALAR_BYTES;
    pub const PUBLIC_BYTES: usize = 64;
    pub const STATIC_PUBLIC: usize = EPHEMERAL_PUBLIC + PUBLIC_BYTES;
    pub const ID_LENGTH: usize = STATIC_PUBLIC + PUBLIC_BYTES;
    pub const ID: usize = ID_LENGTH + 1;
    pub const ID_CAPACITY: usize = 32;
    pub const SIZE: usize = ID + ID_CAPACITY;
}
// Bounded non-streaming request capacity in bytes (including Ed25519 messages).
pub const INPUT_BYTES: usize = 544;
// RSA-4096 output (512 bytes) plus room for protocol wrappers.
pub const OUTPUT_BYTES: usize = 528;
pub struct Workspace {
    pub key: KeyMaterial,
    #[cfg(feature = "piv")]
    pub agreement: [u8; agreement_layout::SIZE],
    pub input: [u8; INPUT_BYTES],
    pub output: [u8; OUTPUT_BYTES],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            key: KeyMaterial::new(),
            #[cfg(feature = "piv")]
            agreement: [0; agreement_layout::SIZE],
            input: [0; INPUT_BYTES],
            output: [0; OUTPUT_BYTES],
        }
    }
    pub fn clear(&mut self, memory: &dyn Memory) {
        #[cfg(feature = "piv")]
        memory.wipe(&mut self.agreement);
        memory.wipe(&mut self.key.bytes);
        self.key.bits = 0;
        self.key.reserved = 0;
        memory.wipe(&mut self.input);
        memory.wipe(&mut self.output);
    }
}

/// Alternative views of the same session reservation. Streaming PQ operations
/// never coexist with a classic RSA key/input/result workspace.
#[allow(clippy::large_enum_variant)]
pub enum SessionWorkspace {
    Classic(Workspace),
    #[cfg(feature = "piv")]
    Stream(crate::ports::CryptoScratch),
    #[cfg(feature = "piv")]
    Attestation(crate::applets::piv::attestation::Attestation),
}
impl SessionWorkspace {
    pub const fn new() -> Self {
        Self::Classic(Workspace::new())
    }
    #[inline(never)]
    pub fn classic(&mut self) -> &mut Workspace {
        #[cfg(feature = "piv")]
        if !matches!(self, Self::Classic(_)) {
            *self = Self::Classic(Workspace::new());
        }
        match self {
            Self::Classic(w) => w,
            #[cfg(feature = "piv")]
            _ => unreachable!(),
        }
    }
    #[cfg(feature = "piv")]
    #[inline(never)]
    pub fn stream(&mut self) -> &mut crate::ports::CryptoScratch {
        *self = Self::Stream(crate::ports::CryptoScratch::new());
        let Self::Stream(s) = self else {
            unreachable!()
        };
        s
    }
    #[cfg(feature = "piv")]
    #[inline(never)]
    pub fn attestation(&mut self) -> &mut crate::applets::piv::attestation::Attestation {
        *self = Self::Attestation(crate::applets::piv::attestation::Attestation::new());
        let Self::Attestation(a) = self else {
            unreachable!()
        };
        a
    }
}
