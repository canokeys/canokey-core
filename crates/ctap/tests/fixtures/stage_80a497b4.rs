// SPDX-License-Identifier: Apache-2.0
// Fixed Core 80a497b4 certificate staging implementation. Only cfg/imports,
// the Platform type and record-specific backend method names are projected.
use canokey_ctap::ports::CertificateStage;
pub const CERT_LIMIT: usize = 1152;
#[derive(Debug, PartialEq, Eq)]
pub enum Error { Length, Storage, NotActive }
pub struct Platform<'a, S> { pub storage: &'a mut S }
pub(crate) struct Certificate {
    active: bool,
}
impl Certificate {
    pub const fn new() -> Self {
        Self { active: false }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn begin(
        &mut self,
        p: &mut Platform<'_, impl CertificateStage<Error = u8>>,
    ) -> Result<(), Error> {
        p.storage.begin().map_err(|_| Error::Storage)?;
        self.active = true;
        Ok(())
    }
    pub fn append(
        &mut self,
        used: &mut usize,
        bytes: &[u8],
        p: &mut Platform<'_, impl CertificateStage<Error = u8>>,
    ) -> Result<(), Error> {
        *used = used
            .checked_add(bytes.len())
            .filter(|n| *n <= CERT_LIMIT)
            .ok_or(Error::Length)?;
        p.storage.append(bytes).map_err(|_| Error::Storage)
    }
    pub fn commit(
        &mut self,
        p: &mut Platform<'_, impl CertificateStage<Error = u8>>,
    ) -> Result<(), Error> {
        if !self.active {
            return Err(Error::NotActive);
        }
        p.storage
            .commit()
            .map_err(|_| Error::Storage)?;
        self.active = false;
        Ok(())
    }
    pub fn abort(&mut self, p: &mut Platform<'_, impl CertificateStage<Error = u8>>) {
        if self.active {
            p.storage.abort();
            self.active = false;
        }
    }
}
