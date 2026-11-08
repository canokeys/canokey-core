// SPDX-License-Identifier: Apache-2.0
//! Synchronous chip IO used while the product facade owns its IRQ state.
/// Implementations complete IO before returning and retain no borrowed slices.
/// They must not reenter the transport runtime while its state is borrowed.
pub trait Chip {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool;
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool;
}
