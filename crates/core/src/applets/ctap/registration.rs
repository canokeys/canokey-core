// SPDX-License-Identifier: Apache-2.0
//! Deferred resident publication owns only a staged record capability. Request
//! fields and primitive scratch remain with their existing workspace owners.
use super::Status;
use crate::ports::{Record, Storage};
use core::num::NonZeroU8;

// CTAP group record IDs are nonzero. Keep the optional publication in one byte
// without changing the durable record namespace or retaining request backing.
pub(super) type Publication = NonZeroU8;
pub(super) struct Pending(canokey_ctap::registration::Pending<(), Publication>);
const _: () = assert!(Record::CTAP_GROUP_BASE != 0x00);
const _: () = assert!(core::mem::size_of::<Pending>() == 1);

pub(super) fn publication(record: Record) -> Result<Publication, Status> {
    NonZeroU8::new(record.id()).ok_or(Status::Other)
}

pub(super) struct Publisher<'a, S: ?Sized>(pub &'a mut S);
impl<C, S: Storage + ?Sized> canokey_ctap::registration::Publisher<C, Publication>
    for Publisher<'_, S>
{
    type Error = Status;
    fn commit(&mut self, _: &C, record: &Publication) -> Result<(), Status> {
        let record = Record::from_id(record.get()).ok_or(Status::Other)?;
        self.0.stage_commit(record).map_err(|_| Status::Other)
    }
    fn abort(&mut self, _: &Publication) {
        self.0.stage_abort();
    }
}

impl Pending {
    pub const fn empty() -> Self {
        Self(canokey_ctap::registration::Pending::empty(()))
    }
    pub fn new(pending: canokey_ctap::registration::Pending<(), Publication>) -> Self {
        Self(pending)
    }
    pub fn is_resident(&self) -> bool {
        self.0.is_resident()
    }
    pub fn finish(
        &mut self,
        response: Result<(), Status>,
        storage: &mut (impl Storage + ?Sized),
    ) -> Result<(), Status> {
        self.0.take().finish(response, &mut Publisher(storage))
    }
    #[inline(always)]
    pub fn abort(&mut self, storage: &mut (impl Storage + ?Sized)) -> bool {
        let staged = self.is_resident();
        self.0.take().cancel(&mut Publisher(storage));
        staged
    }
}
