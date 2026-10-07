// SPDX-License-Identifier: Apache-2.0
//! One session-owned workspace, lent by the registry to the selected applet.
//! Key material, crypto input and result are simultaneously live at the crypto
//! boundary. Certificates and encoded import messages never occupy this area.
use crate::ports::KeyMaterial;
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
/// A temporary split borrow of the classic fields in the session reservation.
pub struct Workspace<'a> {
    #[cfg_attr(not(crypto_applet), expect(dead_code))]
    pub key: &'a mut KeyMaterial,
    #[cfg(feature = "piv")]
    pub agreement: &'a mut [u8; agreement_layout::SIZE],
    pub input: &'a mut [u8; INPUT_BYTES],
    pub output: &'a mut [u8; OUTPUT_BYTES],
}
impl Workspace<'_> {
    #[cfg_attr(not(crypto_applet), expect(dead_code))]
    pub fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        clear_classic(
            self.key,
            self.input,
            #[cfg(feature = "piv")]
            self.agreement,
            memory,
        );
        memory.wipe(self.output);
    }
}
pub(crate) struct Classic {
    pub key: KeyMaterial,
    #[cfg(feature = "piv")]
    pub agreement: [u8; agreement_layout::SIZE],
    pub input: [u8; INPUT_BYTES],
}
impl Classic {
    const fn new() -> Self {
        Self {
            key: KeyMaterial::new(),
            #[cfg(feature = "piv")]
            agreement: [0; agreement_layout::SIZE],
            input: [0; INPUT_BYTES],
        }
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        clear_classic(
            &mut self.key,
            &mut self.input,
            #[cfg(feature = "piv")]
            &mut self.agreement,
            memory,
        );
    }
}
fn clear_classic(
    key: &mut KeyMaterial,
    input: &mut [u8; INPUT_BYTES],
    #[cfg(feature = "piv")] agreement: &mut [u8; agreement_layout::SIZE],
    memory: &crate::ports::MemoryPort<'_>,
) {
    #[cfg(feature = "piv")]
    memory.wipe(agreement);
    memory.wipe(&mut key.bytes);
    key.bits = 0;
    key.reserved = 0;
    memory.wipe(input);
}
macro_rules! workspace_view {
    ($(#[$attr:meta])* $with:ident, $plain:ident, $variant:ident, $ty:ty, $reuse:expr) => {
        $(#[$attr])*
        pub fn $with(&mut self, memory: &crate::ports::MemoryPort<'_>) -> &mut $ty {
            if !$reuse || !matches!(self, Self::$variant(_)) {
                self.wipe_active(memory);
                *self = Self::$variant(<$ty>::new());
            }
            let Self::$variant(view) = self else { unreachable!() };
            view
        }
        $(#[$attr])*
        pub fn $plain(&mut self) -> &mut $ty {
            let memory = canokey_ports::default_memory();
            self.$with(&memory)
        }
    };
}
#[allow(clippy::large_enum_variant)]
pub(crate) enum Primitive {
    Classic(Classic),
    #[cfg(feature = "ctap")]
    Ctap(crate::ports::CryptoScratch),
}
/// Response bytes survive the classic-to-PQ primitive transition in place.
pub struct Working {
    pub(crate) primitive: Primitive,
    #[cfg(feature = "ctap")]
    pub(crate) framing: crate::applets::ctap::pq::Framing,
    #[cfg(not(feature = "ctap"))]
    output: [u8; OUTPUT_BYTES],
}
impl Working {
    const fn new() -> Self {
        Self {
            primitive: Primitive::Classic(Classic::new()),
            #[cfg(feature = "ctap")]
            framing: crate::applets::ctap::pq::Framing::new(),
            #[cfg(not(feature = "ctap"))]
            output: [0; OUTPUT_BYTES],
        }
    }
    fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        match &mut self.primitive {
            Primitive::Classic(c) => c.clear(memory),
            #[cfg(feature = "ctap")]
            Primitive::Ctap(c) => memory.wipe(&mut c.bytes),
        }
        #[cfg(feature = "ctap")]
        self.framing.clear(memory);
        #[cfg(not(feature = "ctap"))]
        memory.wipe(&mut self.output);
    }
}

/// Alternative views of the same session reservation. Streaming PQ operations
/// never coexist with a classic RSA key/input/result workspace.
#[allow(clippy::large_enum_variant)]
pub enum SessionWorkspace {
    Working(Working),
    #[cfg(feature = "ctap")]
    CtapRequest(crate::applets::ctap::Request),
    #[cfg(feature = "ctap")]
    CtapMessage(crate::applets::ctap::message::MessageParser),
    #[cfg(feature = "ctap")]
    U2fRequest(crate::applets::ctap::u2f::Request),
    #[cfg(feature = "piv")]
    Stream(crate::ports::CryptoScratch),
    #[cfg(feature = "piv")]
    Attestation(crate::applets::piv::attestation::Attestation),
}
impl SessionWorkspace {
    pub const fn new() -> Self {
        Self::Working(Working::new())
    }
    pub(crate) fn wipe_active(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        match self {
            Self::Working(w) => w.clear(memory),
            #[cfg(feature = "ctap")]
            Self::U2fRequest(r) => r.clear(memory),
            #[cfg(feature = "piv")]
            Self::Stream(s) => memory.wipe(&mut s.bytes),
            #[cfg(feature = "piv")]
            Self::Attestation(a) => a.clear(memory),
            #[cfg(feature = "ctap")]
            Self::CtapRequest(request) => request.clear(memory),
            #[cfg(feature = "ctap")]
            Self::CtapMessage(request) => request.clear(memory),
        }
    }
    #[inline(never)]
    pub fn classic_with(&mut self, memory: &crate::ports::MemoryPort<'_>) -> Workspace<'_> {
        if !matches!(
            self,
            Self::Working(Working {
                primitive: Primitive::Classic(_),
                ..
            })
        ) {
            self.wipe_active(memory);
            *self = Self::Working(Working::new());
        }
        let w = match self {
            Self::Working(w) => w,
            #[cfg(any(feature = "piv", feature = "ctap"))]
            _ => unreachable!(),
        };
        let c = match &mut w.primitive {
            Primitive::Classic(c) => c,
            #[cfg(feature = "ctap")]
            _ => unreachable!(),
        };
        Workspace {
            key: &mut c.key,
            #[cfg(feature = "piv")]
            agreement: &mut c.agreement,
            input: &mut c.input,
            #[cfg(feature = "ctap")]
            output: (&mut w.framing.bytes[..OUTPUT_BYTES]).try_into().unwrap(),
            #[cfg(not(feature = "ctap"))]
            output: &mut w.output,
        }
    }
    #[cfg(any(feature = "piv", feature = "ctap"))]
    #[inline(never)]
    pub fn classic(&mut self) -> Workspace<'_> {
        let memory = canokey_ports::default_memory();
        self.classic_with(&memory)
    }
    #[cfg(feature = "ctap")]
    pub(crate) fn ctap_stream(&mut self) -> Option<crate::applets::ctap::pq::Stream<'_>> {
        if let Self::Working(Working {
            primitive: Primitive::Ctap(crypto),
            framing,
        }) = self
        {
            Some(crate::applets::ctap::pq::Stream { crypto, framing })
        } else {
            None
        }
    }
    workspace_view!(
        #[cfg(feature = "ctap")]
        ctap_request_with,
        ctap_request,
        CtapRequest,
        crate::applets::ctap::Request,
        true
    );
    #[cfg(feature = "ctap")]
    pub fn cancel_ctap_request(&mut self) {
        if let Self::CtapRequest(request) = self {
            let memory = canokey_ports::default_memory();
            request.clear(&memory);
            *request = crate::applets::ctap::Request::new();
        }
    }
    workspace_view!(
        #[cfg(feature = "piv")]
        #[inline(never)]
        stream_with,
        stream,
        Stream,
        crate::ports::CryptoScratch,
        false
    );
    workspace_view!(
        #[cfg(feature = "piv")]
        #[inline(never)]
        attestation_with,
        attestation,
        Attestation,
        crate::applets::piv::attestation::Attestation,
        false
    );
}
