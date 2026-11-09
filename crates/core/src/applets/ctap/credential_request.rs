// SPDX-License-Identifier: Apache-2.0
//! Product capacities and direct Command publication for the shared parser.
use super::{Command, Status};
pub(super) use canokey_ctap::request::credential::MAX_LIST;
pub type Parameters = canokey_ctap::request::credential::Parameters<{ super::MAX_REQUEST / 20 }>;
pub struct Parser(
    canokey_ctap::request::credential::Parser<
        Status,
        { super::MAX_REQUEST / 20 },
        { (super::MAX_REQUEST - 1) as u16 },
    >,
);
impl Parser {
    pub const fn new(make: bool) -> Self {
        Self(canokey_ctap::request::credential::Parser::new(make))
    }
    pub fn consume(&mut self, bytes: &[u8]) {
        self.0.consume(bytes);
    }
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        self.0.clear(memory);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.0
            .finish_with(&canokey_ports::default_memory(), Command::Credential)
    }
}
