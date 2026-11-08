// SPDX-License-Identifier: Apache-2.0
//! Scoped loans of product-owned workspace; no payload allocation or callbacks.
use canokey_ports::Memory;

/// A mutable reservation stays provisional until its caller publishes it.
/// Dropping an unpublished loan wipes its entire borrowed region, including
/// unwritten bytes. Scratch callers never publish; output callers publish only
/// after validation, before advancing their response cursor. The loan cannot
/// retain an application, storage or transport capability.
pub struct Reservation<'a, M: Memory + ?Sized> {
    bytes: &'a mut [u8],
    memory: &'a M,
    published: bool,
}
impl<'a, M: Memory + ?Sized> Reservation<'a, M> {
    pub fn new(bytes: &'a mut [u8], memory: &'a M) -> Self {
        Self {
            bytes,
            memory,
            published: false,
        }
    }
    pub fn bytes(&mut self) -> &mut [u8] {
        self.bytes
    }
    /// End the exclusive loan and retain validated output in its original
    /// backing. No slice escapes; the product regains its own backing borrow.
    pub fn publish(mut self) {
        self.published = true;
    }
}
impl<M: Memory + ?Sized> Drop for Reservation<'_, M> {
    fn drop(&mut self) {
        if !self.published {
            self.memory.wipe(self.bytes);
        }
    }
}
