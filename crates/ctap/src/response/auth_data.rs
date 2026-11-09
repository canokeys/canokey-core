// SPDX-License-Identifier: Apache-2.0
//! WebAuthn authenticatorData offsets and fixed headers, in network byte order.

pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const AT: u8 = 0x40;
pub const ED: u8 = 0x80;
pub const FLAGS_OFFSET: usize = 32;
pub const COUNTER_OFFSET: usize = FLAGS_OFFSET + 1;
pub const HEADER_BYTES: usize = COUNTER_OFFSET + 4;
pub const CREDENTIAL_LENGTH_OFFSET: usize = HEADER_BYTES + 16; // AAGUID16.
pub const CREDENTIAL_OFFSET: usize = CREDENTIAL_LENGTH_OFFSET + 2;

/// rpIdHash(32), flags(1), signature counter(4), as WebAuthn section 6.1.
/// The caller reads the counter and owns extension flags and output publication.
#[inline(always)]
pub fn header(output: &mut [u8], rp: &[u8; 32], counter: &[u8; 4], up: bool, uv: bool, make: bool) {
    output[..FLAGS_OFFSET].copy_from_slice(rp);
    output[FLAGS_OFFSET] =
        if up { UP } else { 0x00 } | if uv { UV } else { 0x00 } | if make { AT } else { 0x00 };
    output[COUNTER_OFFSET..HEADER_BYTES].copy_from_slice(counter);
}
/// Attested credential data: AAGUID(16), ID length(u16 bytes), ID.
/// Products admit the credential ID and lend a sufficiently sized authData view.
#[inline(always)]
pub fn attested(output: &mut [u8], aaguid: &[u8; 16], id: &[u8]) {
    output[HEADER_BYTES..CREDENTIAL_LENGTH_OFFSET].copy_from_slice(aaguid);
    output[CREDENTIAL_LENGTH_OFFSET..CREDENTIAL_OFFSET]
        .copy_from_slice(&(id.len() as u16).to_be_bytes());
    output[CREDENTIAL_OFFSET..CREDENTIAL_OFFSET + id.len()].copy_from_slice(id);
}

/// ED may precede registration public-key work or follow its successful output.
/// This distinction preserves the consumers' error/partial-output ordering.
#[derive(Clone, Copy)]
pub enum ExtensionFlag {
    BeforeAttested,
    AfterPublic,
}
pub struct Construction<'a> {
    pub rp: &'a [u8; 32],
    pub counter: &'a [u8; 4],
    pub up: bool,
    pub uv: bool,
    pub make: bool,
    pub extension_flag: ExtensionFlag,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Constructed {
    Complete(usize),
    ExternalPublic,
}
/// All methods are synchronous loans of existing output/scratch. Public is only
/// preparation metadata (or unit); implementations must not add key backing or
/// retain data slices across crypto, progress, storage or transport boundaries.
pub trait Constructor {
    type Error;
    type Public;
    type Extensions;
    fn data(&mut self) -> &mut [u8];
    fn prepare_public(&mut self) -> Result<Self::Public, Self::Error>;
    fn public(&mut self, cursor: usize, prepared: Self::Public) -> Result<usize, Self::Error>;
    /// Append the shared attested header over the existing product ID/AAGUID,
    /// returning the COSE cursor. Metadata is read after public preparation.
    fn attested(&mut self) -> usize;
    #[inline(always)]
    fn external_public(&self) -> bool {
        false
    }
    fn prepare_extensions(&self) -> Option<Self::Extensions>;
    /// Returns the absolute cursor within output, after encoding extensions.
    fn extensions(
        &mut self,
        cursor: usize,
        prepared: Self::Extensions,
    ) -> Result<usize, Self::Error>;
    #[inline(always)]
    fn late_extensions(mut self, cursor: usize) -> Result<usize, Self::Error>
    where
        Self: Sized,
    {
        if let Some(prepared) = self.prepare_extensions() {
            self.data()[FLAGS_OFFSET] |= ED;
            self.extensions(cursor, prepared)
        } else {
            Ok(cursor)
        }
    }
}
/// Assemble authenticatorData over the caller's fixed buffer. Counter IO occurs
/// before entry; public-key generation and extension preparation run only at
/// their original wire positions. Publication and signing follow successful
/// construction in the existing owner. No complete data or key copy is added.
#[inline(always)]
pub fn construct<B: Constructor>(
    fields: Construction<'_>,
    mut backend: B,
) -> Result<Constructed, B::Error> {
    let make = fields.make;
    header(
        backend.data(),
        fields.rp,
        fields.counter,
        fields.up,
        fields.uv,
        make,
    );
    if make && backend.external_public() {
        return Ok(Constructed::ExternalPublic);
    }
    let early_extensions = if matches!(fields.extension_flag, ExtensionFlag::BeforeAttested) {
        backend.prepare_extensions()
    } else {
        None
    };
    if early_extensions.is_some() {
        backend.data()[FLAGS_OFFSET] |= ED;
    }
    let mut cursor = HEADER_BYTES;
    if make {
        let prepared = backend.prepare_public()?;
        cursor = backend.attested();
        cursor = backend.public(cursor, prepared)?;
    }
    if matches!(fields.extension_flag, ExtensionFlag::BeforeAttested) {
        if let Some(prepared) = early_extensions {
            cursor = backend.extensions(cursor, prepared)?;
        }
    } else {
        cursor = backend.late_extensions(cursor)?;
    }
    Ok(Constructed::Complete(cursor))
}

/// Statically borrowed contexts keep the existing workspace/platform ABI; no
/// aggregate callback object or complete data copy crosses the outlined stage.
pub trait ExtensionConstructor {
    type Request: ?Sized;
    type Workspace: ?Sized;
    type Platform: ?Sized;
    type Prepared;
    type Error;
    fn prepare(request: &Self::Request) -> Option<Self::Prepared>;
    fn data(workspace: &mut Self::Workspace) -> &mut [u8];
    fn encode(
        request: &Self::Request,
        workspace: &mut Self::Workspace,
        platform: &mut Self::Platform,
        cursor: usize,
        prepared: Self::Prepared,
    ) -> Result<usize, Self::Error>;
}
/// Presence/count admission, ED and encoding stay in one outlined stage for
/// ordinary and streamed registration. Public-key work retains no extension
/// metadata. Each context is an existing borrowed object, passed separately.
#[inline(never)]
pub fn extend<B: ExtensionConstructor>(
    request: &B::Request,
    workspace: &mut B::Workspace,
    platform: &mut B::Platform,
    cursor: usize,
) -> Result<usize, B::Error> {
    if let Some(prepared) = B::prepare(request) {
        B::data(workspace)[FLAGS_OFFSET] |= ED;
        B::encode(request, workspace, platform, cursor, prepared)
    } else {
        Ok(cursor)
    }
}
