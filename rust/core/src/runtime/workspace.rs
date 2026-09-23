// SPDX-License-Identifier: Apache-2.0
//! One session-owned workspace, lent by the registry to the selected applet.
//! Key material, crypto input and result are simultaneously live at the crypto
//! boundary. Certificates and encoded import messages never occupy this area.
use crate::ports::{KeyMaterial, Memory};
pub struct Workspace {
    pub key: KeyMaterial,
    #[cfg(feature = "piv")]
    pub agreement: [u8; 193],
    pub input: [u8; 544],
    pub output: [u8; 528],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            key: KeyMaterial::new(),
            #[cfg(feature = "piv")]
            agreement: [0; 193],
            input: [0; 544],
            output: [0; 528],
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
