// SPDX-License-Identifier: Apache-2.0
//! Product workspace transition and provisioned material for the shared PQ engine.
use super::Status;
use crate::{
    ports::{Backends, CryptoScratch, Platform},
    runtime::workspace::{Primitive, SessionWorkspace},
};
use canokey_ctap::streaming as shared;
use canokey_protocol::response::StatusWord as Sw;
#[cfg(test)]
use shared::FRAMING_BYTES;
pub use shared::{Framing, Mode, Pending};

struct Profile;
impl<B: Backends> shared::Profile<B> for Profile {
    type Error = Status;
    #[inline(always)]
    fn invalid() -> Status {
        Status::Other
    }
    #[inline(always)]
    fn cancelled() -> Status {
        Status::Cancelled
    }
    #[inline(always)]
    fn key(output: &mut [u8; 32], p: &mut Platform<'_, B>) -> Result<(), Status> {
        super::attestation::key(output, p).map_err(|_| Status::Other)
    }
    #[inline(always)]
    fn certificate(offset: u32, output: &mut [u8], p: &mut Platform<'_, B>) -> Result<(), Sw> {
        canokey_ctap::response::certificate(
            &mut super::adapter::Certificate(p.storage),
            offset,
            output,
            canokey_ctap::response::ReadMode::Exact,
        )
        .map(|_| ())
        .map_err(|_| Sw::UNABLE_TO_PROCESS)
    }
}
pub struct Stream<'a> {
    pub(crate) crypto: &'a mut CryptoScratch,
    pub(crate) framing: &'a mut Framing,
}
impl Stream<'_> {
    #[inline(always)]
    fn shared(&mut self) -> shared::Stream<'_> {
        shared::Stream {
            crypto: self.crypto,
            framing: self.framing,
        }
    }
    #[inline(never)]
    fn transfer(
        plan: Pending,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl Backends>,
    ) -> Result<(), Status> {
        let SessionWorkspace::Working(w) = w else {
            unreachable!()
        };
        let Primitive::Classic(old) = &mut w.primitive else {
            unreachable!()
        };
        let framing = &mut w.framing;
        let params = framing
            .stage(plan, old.input.as_slice(), p.memory)
            .map_err(|()| Status::Other)?;
        old.clear(p.memory);
        w.primitive = Primitive::Ctap(CryptoScratch::new());
        framing.activate(plan, params);
        Ok(())
    }
    pub fn prepare(
        plan: Pending,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl Backends>,
    ) -> Result<usize, Status> {
        Self::transfer(plan, w, p)?;
        w.ctap_stream()
            .unwrap()
            .shared()
            .prepare::<Profile, _>(plan, p)
    }
    pub fn read(
        &mut self,
        offset: usize,
        output: &mut [u8],
        p: &mut Platform<'_, impl Backends>,
    ) -> Result<(), Sw> {
        self.shared().read::<Profile, _>(offset, output, p)
    }
    pub fn close(&mut self, p: &mut Platform<'_, impl Backends>) {
        self.shared().close(p);
    }
}
#[cfg(test)]
mod tests;
