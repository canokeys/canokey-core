// SPDX-License-Identifier: Apache-2.0
pub trait Device {
    fn serial(&mut self, output: &mut [u8; 4]);
    fn now(&mut self) -> u32;
    fn touched(&mut self) -> bool;
    /// Transport-only progress; false means reset/disconnect/cancel.
    fn progress(&mut self) -> bool;
    fn led(&mut self, on: bool);
}
